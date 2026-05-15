from __future__ import annotations

import asyncio
import os
from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8_service import IPv8
from ipv8.keyvault.crypto import default_eccrypto

MY_ROUND_NO = 1        # change to 2 or 3 for other teammates
KEY_FILE = "my_key.pem"
GROUP_ID = "495dd63cbdadb77a"
RETRY = 0.05
received_sigs = [False, False, False]  # tracks which member indices we've already stored

SERVER_PUBLIC_KEY_BIN = bytes.fromhex(
    "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96"
)
COMMUNITY_ID = bytes.fromhex("4c61623247726f75705369676e696e6732303236")

#Payloads

@vp_compile
class ChallengeRequest(VariablePayload):
    msg_id = 3
    format_list = ["varlenHutf8"]
    names = ["group_id"]

@vp_compile
class ChallengeResponse(VariablePayload):
    msg_id = 4
    format_list = ["varlenH", "q", "d"]
    names = ["nonce", "round_number", "deadline"]

@vp_compile
class SignatureBundle(VariablePayload):
    msg_id = 5
    format_list = ["varlenHutf8", "q", "varlenH", "varlenH", "varlenH"]
    names = ["group_id", "round_number", "sig1", "sig2", "sig3"]

@vp_compile
class RoundResult(VariablePayload):
    msg_id = 6
    format_list = ["?", "q", "q", "varlenHutf8"]
    names = ["success", "round_number", "rounds_completed", "message"]

@vp_compile
class NonceShare(VariablePayload):
    msg_id = 7
    format_list = ["varlenH", "q"]
    names = ["nonce", "round_number"]

@vp_compile
class SigShare(VariablePayload):
    msg_id = 8
    format_list = ["varlenH", "q", "q"]
    names = ["signature", "round_number", "member_index"]

@vp_compile
class RoundComplete(VariablePayload):
    msg_id = 9
    format_list = ["q"]
    names = ["round_number"]

#COMMUNITY

class Lab2(Community):
    community_id = COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)

        self.member_keys = [
            getattr(settings, "member_1", b""),
            getattr(settings, "member_2", b""),
            getattr(settings, "member_3", b""),
        ]
        with open(KEY_FILE, "rb") as f:
            self.private_key = default_eccrypto.key_from_private_bin(f.read())

        self.current_round = 1
        self.nonce = None
        self.sigs = [None, None, None]

        self.done = asyncio.Event()

        self.add_message_handler(ChallengeResponse, self.on_challenge_response)
        self.add_message_handler(RoundResult, self.on_round_result)
        self.add_message_handler(NonceShare, self.on_nonce_share)
        self.add_message_handler(SigShare, self.on_sig_share)
        self.add_message_handler(RoundComplete, self.on_round_complete)

    def _server(self) -> Peer | None:
        for peer in self.get_peers():
            if peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY_BIN:
                return peer
        return None

    def _teammates(self) -> list[Peer]:
        return [
            peer for peer in self.get_peers()
            if peer.public_key.key_to_bin() in self.member_keys
            and peer.public_key.key_to_bin() != self.member_keys[MY_ROUND_NO - 1]
        ]

    def _coordinator(self) -> Peer | None:
        coord_key = self.member_keys[self.current_round - 1]
        for peer in self.get_peers():
            if peer.public_key.key_to_bin() == coord_key:
                return peer
        return None

    def started(self) -> None:
        self.register_task("tick", self._tick, interval=RETRY, delay=0.0)

    async def _tick(self) -> None:
        server = self._server()
        if not server:
            return

        if self.current_round == MY_ROUND_NO:
            if self.nonce is None:
                self.ez_send(server, ChallengeRequest(GROUP_ID))
            elif all(s is not None for s in self.sigs):
                self.ez_send(server, SignatureBundle(GROUP_ID, self.current_round, *self.sigs))
            else:
                for teammate in self._teammates():
                    self.ez_send(teammate, NonceShare(self.nonce, self.current_round))
        else:
            coord = self._coordinator()
            if self.sigs[MY_ROUND_NO - 1] and coord:
                self.ez_send(coord, SigShare(self.sigs[MY_ROUND_NO - 1], self.current_round, MY_ROUND_NO - 1))

    @lazy_wrapper(ChallengeResponse)
    def on_challenge_response(self, peer: Peer, payload: ChallengeResponse) -> None:
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY_BIN or self.nonce:
            return
        print(f"[Round {payload.round_number}] Nonce received, deadline={payload.deadline:.2f}")
        self.nonce = payload.nonce
        self.sigs[MY_ROUND_NO - 1] = self.private_key.signature(self.nonce)
        for teammate in self._teammates():
            self.ez_send(teammate, NonceShare(self.nonce, self.current_round))

    @lazy_wrapper(NonceShare)
    def on_nonce_share(self, peer: Peer, payload: NonceShare) -> None:
        # advance state if coordinator is already on the next round
        if payload.round_number > self.current_round:
            self.current_round = payload.round_number
            self.nonce = None
            self.sigs = [None, None, None]

        if payload.round_number != self.current_round or self.sigs[MY_ROUND_NO - 1]:
            return

        self.sigs[MY_ROUND_NO - 1] = self.private_key.signature(payload.nonce)
        self.ez_send(peer, SigShare(self.sigs[MY_ROUND_NO - 1], self.current_round, MY_ROUND_NO - 1))

    @lazy_wrapper(SigShare)
    def on_sig_share(self, _peer: Peer, payload: SigShare) -> None:
        if payload.round_number == self.current_round and not received_sigs[payload.member_index]:
            received_sigs[payload.member_index] = True
            self.sigs[payload.member_index] = payload.signature

    @lazy_wrapper(RoundResult)
    def on_round_result(self, peer: Peer, payload: RoundResult) -> None:
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY_BIN:
            return
        print(f"[Round {payload.round_number}] {payload.message}")
        if not payload.success:
            return
        if payload.rounds_completed == 3:
            for teammate in self._teammates():
                self.ez_send(teammate, RoundComplete(payload.round_number))
            self.cancel_pending_task("tick")
            self.done.set()
            return
        self.current_round += 1
        self.nonce = None
        self.sigs = [None, None, None]
        received_sigs[:] = [False, False, False]
        for teammate in self._teammates():
            self.ez_send(teammate, RoundComplete(payload.round_number))

    @lazy_wrapper(RoundComplete)
    def on_round_complete(self, _peer: Peer, payload: RoundComplete) -> None:
        if payload.round_number == self.current_round:
            self.current_round += 1
            self.nonce = None
            self.sigs = [None, None, None]
        if payload.round_number == 3:
            self.cancel_pending_task("tick")
            self.done.set()

# Initializing and Running the client

async def run_client(member: dict) -> None:
    builder = (
        ConfigBuilder()
        .clear_keys()
        .clear_overlays()
        .add_key("my_key", "curve25519", KEY_FILE)
        .add_overlay(
            "Lab2",
            "my_key",
            [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 3.0})],
            default_bootstrap_defs,
            {"member_1": member["adithya"], "member_2": member["dyujoy"], "member_3": member["sadi"]},
            [("started",)],
        )
    )

    ipv8 = IPv8(builder.finalize(), extra_communities={"Lab2": Lab2})
    await ipv8.start()

    community: Lab2 = ipv8.overlays[0]
    print(f"[Info] my_index={MY_ROUND_NO - 1}  coordinator for round {MY_ROUND_NO}")

    try:
        await asyncio.wait_for(community.done.wait(), timeout=300.0)
    except asyncio.TimeoutError:
        print("[Net] Timed out (300s).")
    finally:
        await ipv8.stop()

if __name__ == "__main__":
    dir = "keys"
    member = {}
    for file in os.listdir(dir):
        with open(os.path.join("keys", file), "rb") as f:
            key = default_eccrypto.key_from_private_bin(f.read())
            member[file.replace(".pem", "")] = key.pub().key_to_bin()
    asyncio.run(run_client(member))
