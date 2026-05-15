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

KEY_FILE = "my_key.pem" 
SERVER_PUBLIC_KEY_BIN = bytes.fromhex(
    "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96"
)
COMMUNITY_ID=bytes.fromhex("4c61623247726f75705369676e696e6732303236")

@vp_compile
class registerMessage (VariablePayload):
    msg_id=1
    format_list=["varlenH","varlenH","varlenH"]
    names=["member1_key","member2_key","member3_key"]

@vp_compile
class ResponseMessage(VariablePayload):
    msg_id=2
    format_list=["?","varlenHutf8","varlenHutf8"]
    names=["success","group_id","message"]

class Lab2(Community):
    community_id = COMMUNITY_ID
    def __init__(self,settings:CommunitySettings)->None:
        super().__init__(settings)
        self.done:asyncio.Event=asyncio.Event()
        self.member1=getattr(settings,"member_1","")
        self.member2=getattr(settings,"member_2","")
        self.member3=getattr(settings,"member_3","")
        self.add_message_handler(ResponseMessage,self.onResponse)
    


    async def _find_and_submit(self) -> None:
        """Scan visible peers for the server; send submission on first match."""
        peers = self.get_peers()
        for peer in peers:
            if peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY_BIN:
                print(f"[Net] Server found at {peer.address} — sending submission …")
                self.cancel_pending_task("find_server")
                self.ez_send(peer, registerMessage(self.member1, self.member2, self.member3))
                print("[Net] Submission sent — waiting for server response …")
                return
        print(f"[Net] Searching for server … {len(peers)} peer(s) visible so far")


    @lazy_wrapper(ResponseMessage)
    def onResponse(self,peer:Peer,payload:ResponseMessage)->None:
        if payload.success:
            print(f"The message from the server is {payload.message}")
            print(f"Success, the group ID is {payload.group_id}")
        self.done.set()


    def started(self) -> None:
        """Register a periodic task to locate the server and send the submission."""
        self.register_task("find_server", self._find_and_submit, interval=2.0, delay=2.0)

async def run_client(member) -> None:
    """Start IPv8, wait for the server response, then shut down cleanly."""
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

    ipv8 = IPv8(builder.finalize(), extra_communities={"Lab2":Lab2})
    await ipv8.start()

    community: Lab2 = ipv8.overlays[0]

    try:
        # Wait up to 5 minutes for the server to respond
        await asyncio.wait_for(community.done.wait(), timeout=300.0)
    except asyncio.TimeoutError:
        print("[Net] Timed out (300s) waiting for server response.")
        print("[Net] Possible causes: no route to server, packet signing issue,")
        print("[Net]   or server peer not yet discovered.  Try running again.")
    finally:
        await ipv8.stop()

if __name__=="__main__":
    dir="keys"
    member={}
    for file in os.listdir(dir):
        with open(os.path.join("keys",file),"rb") as f:
            key=default_eccrypto.key_from_private_bin(f.read())
            member[file.replace(".pem","")]=key.pub().key_to_bin()
    asyncio.run(run_client(member))