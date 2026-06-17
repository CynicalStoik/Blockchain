from __future__ import annotations

import asyncio
import hashlib
import os
import struct
import threading
import time
from dataclasses import dataclass, field

from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8_service import IPv8

# Constants

GROUP_ID = "495dd63cbdadb77a"
DIFFICULTY = 16
BLOCKCHAIN_COMMUNITY_ID = hashlib.sha256(b"Lab3_495dd63cbdadb77a").digest()[:20]
REGISTRATION_COMMUNITY_ID = bytes.fromhex("4c616233426c6f636b636861696e323032365057")
LAB3_SERVER_KEY = bytes.fromhex(
    "4c69624e61434c504b3ae3fc099fb56ca3b5e1de9a1c843387f2acdbb78b1bd43"
    "50ffde518068a0d246344b10d0d8c355fd0d76873e7d7f7838f3715e025af08f7"
    "91324495e083331ce6"
)

# Block primitives

EMPTY_TXSHASH = hashlib.sha256(b"").digest()


def _pack_header(prev_hash: bytes, txs_hash: bytes, timestamp: int, difficulty: int, nonce: int) -> bytes:
    return (prev_hash + txs_hash
            + struct.pack(">Q", timestamp)
            + struct.pack(">I", difficulty)
            + struct.pack(">Q", nonce))


def _block_hash(prev_hash, txs_hash, timestamp, difficulty, nonce) -> bytes:
    return hashlib.sha256(_pack_header(prev_hash, txs_hash, timestamp, difficulty, nonce)).digest()


def _check_pow(h: bytes, difficulty: int) -> bool:
    full, rem = divmod(difficulty, 8)
    for i in range(full):
        if h[i] != 0:
            return False
    if rem and h[full] >= (1 << (8 - rem)):
        return False
    return True


def _tx_hash(sender_key: bytes, data: bytes, timestamp: int, signature: bytes) -> bytes:
    return hashlib.sha256(sender_key + data + struct.pack(">q", timestamp) + signature).digest()


def _txs_hash(hashes: list[bytes]) -> bytes:
    return hashlib.sha256(b"".join(hashes)).digest() if hashes else EMPTY_TXSHASH


@dataclass
class Tx:
    sender_key: bytes
    data: bytes
    timestamp: int
    signature: bytes

    @property
    def hash(self) -> bytes:
        return _tx_hash(self.sender_key, self.data, self.timestamp, self.signature)


@dataclass
class Block:
    height: int
    prev_hash: bytes
    txs_hash: bytes
    timestamp: int
    difficulty: int
    nonce: int
    block_hash: bytes
    txs: list[Tx] = field(default_factory=list)
    raw_tx_hashes: bytes = b""

    @property
    def tx_hashes_bytes(self) -> bytes:
        if self.txs:
            return b"".join(tx.hash for tx in self.txs)
        return self.raw_tx_hashes


def _make_genesis() -> Block:
    ph = b"\x00" * 32
    th = EMPTY_TXSHASH
    bh = _block_hash(ph, th, 0, 0, 0)
    return Block(0, ph, th, 0, 0, 0, bh)


GENESIS = _make_genesis()


def _mine_worker(prev_hash: bytes, txs_hash: bytes, difficulty: int, stop: threading.Event) -> tuple[int, int] | None:
    ts = int(time.time())
    nonce = 0
    while not stop.is_set():
        h = hashlib.sha256(_pack_header(prev_hash, txs_hash, ts, difficulty, nonce)).digest()
        if _check_pow(h, difficulty):
            return nonce, ts
        nonce += 1
        if nonce % 200_000 == 0:
            ts = int(time.time())
    return None


# Registration community payloads

@vp_compile
class RegisterBlockchain(VariablePayload):
    msg_id = 1
    format_list = ["varlenHutf8", "varlenH"]
    names = ["group_id", "community_id"]

@vp_compile
class RegisterResponse(VariablePayload):
    msg_id = 2
    format_list = ["?", "varlenHutf8"]
    names = ["success", "message"]


# Blockchain community payloads

@vp_compile
class SubmitTransaction(VariablePayload):
    msg_id = 1
    format_list = ["varlenH", "varlenH", "q", "varlenH"]
    names = ["sender_key", "data", "timestamp", "signature"]

@vp_compile
class SubmitTransactionResponse(VariablePayload):
    msg_id = 2
    format_list = ["?", "varlenH", "varlenHutf8"]
    names = ["success", "tx_hash", "message"]

@vp_compile
class GetChainHeight(VariablePayload):
    msg_id = 3
    format_list = ["q"]
    names = ["request_id"]

@vp_compile
class ChainHeightResponse(VariablePayload):
    msg_id = 4
    format_list = ["q", "q", "varlenH"]
    names = ["request_id", "height", "tip_hash"]

@vp_compile
class GetBlock(VariablePayload):
    msg_id = 5
    format_list = ["q"]
    names = ["height"]

@vp_compile
class BlockResponse(VariablePayload):
    msg_id = 6
    format_list = ["q", "varlenH", "varlenH", "q", "q", "q", "varlenH", "varlenH"]
    names = ["height", "prev_hash", "txs_hash", "timestamp", "difficulty", "nonce", "block_hash", "tx_hashes"]

@vp_compile
class AnnounceBlock(VariablePayload):
    msg_id = 7
    format_list = ["q", "varlenH", "varlenH", "q", "q", "q", "varlenH", "varlenH"]
    names = ["height", "prev_hash", "txs_hash", "timestamp", "difficulty", "nonce", "block_hash", "tx_hashes"]

@vp_compile
class AnnounceTransaction(VariablePayload):
    msg_id = 8
    format_list = ["varlenH", "varlenH", "q", "varlenH"]
    names = ["sender_key", "data", "timestamp", "signature"]


# Registration Community

class RegistrationCommunity(Community):
    community_id = REGISTRATION_COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.registered = asyncio.Event()
        self.add_message_handler(RegisterResponse, self.on_register_response)

    def _server(self) -> Peer | None:
        for peer in self.get_peers():
            if peer.public_key.key_to_bin() == LAB3_SERVER_KEY:
                return peer
        return None

    def register(self) -> None:
        server = self._server()
        if server:
            self.ez_send(server, RegisterBlockchain(GROUP_ID, BLOCKCHAIN_COMMUNITY_ID))
            print("[Reg] RegisterBlockchain sent")

    @lazy_wrapper(RegisterResponse)
    def on_register_response(self, peer: Peer, payload: RegisterResponse) -> None:
        if peer.public_key.key_to_bin() != LAB3_SERVER_KEY:
            return
        print(f"[Reg] {payload.message}")
        if payload.success:
            self.registered.set()


# Blockchain Community

class BlockchainCommunity(Community):
    community_id = BLOCKCHAIN_COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.member_keys: list[bytes] = [
            getattr(settings, "member_1", b""),
            getattr(settings, "member_2", b""),
            getattr(settings, "member_3", b""),
        ]
        self.chain: dict[int, Block] = {0: GENESIS}
        self.tip: Block = GENESIS
        self.mempool: list[Tx] = []
        self._mempool_hashes: set[bytes] = set()
        self._seen_blocks: set[bytes] = {GENESIS.block_hash}
        self._mine_stop = threading.Event()
        self._mine_task: asyncio.Task | None = None

        self.add_message_handler(SubmitTransaction, self.on_submit_transaction)
        self.add_message_handler(GetChainHeight, self.on_get_chain_height)
        self.add_message_handler(GetBlock, self.on_get_block)
        self.add_message_handler(BlockResponse, self.on_block_response)
        self.add_message_handler(AnnounceBlock, self.on_announce_block)
        self.add_message_handler(AnnounceTransaction, self.on_announce_transaction)

    def _peers(self) -> list[Peer]:
        return [p for p in self.get_peers() if p.public_key.key_to_bin() in self.member_keys]

    def started(self) -> None:
        self.register_task("mine_start", self._begin_mining, delay=2.0)

    async def _begin_mining(self) -> None:
        self._restart_mining()

    def _restart_mining(self) -> None:
        self._mine_stop.set()
        self._mine_stop = threading.Event()
        if self._mine_task and not self._mine_task.done():
            self._mine_task.cancel()
        self._mine_task = asyncio.get_running_loop().create_task(self._mine_loop())

    async def _mine_loop(self) -> None:
        loop = asyncio.get_running_loop()
        stop = self._mine_stop
        while not stop.is_set():
            tip = self.tip
            pending = list(self.mempool)
            th = _txs_hash([tx.hash for tx in pending])
            result = await loop.run_in_executor(None, _mine_worker, tip.block_hash, th, DIFFICULTY, stop)
            if result is None or stop.is_set():
                continue
            nonce, ts = result
            if self.tip.block_hash != tip.block_hash:
                continue
            bh = _block_hash(tip.block_hash, th, ts, DIFFICULTY, nonce)
            new_block = Block(
                height=tip.height + 1,
                prev_hash=tip.block_hash,
                txs_hash=th,
                timestamp=ts,
                difficulty=DIFFICULTY,
                nonce=nonce,
                block_hash=bh,
                txs=pending,
            )
            self._apply_block(new_block)
            print(f"[Chain] Mined block {new_block.height} hash={bh.hex()[:12]}")

    def _validate_block_payload(self, height, prev_hash, txs_hash, timestamp, difficulty, nonce, block_hash, tx_hashes_raw) -> bool:
        expected = _block_hash(prev_hash, txs_hash, timestamp, difficulty, nonce)
        if expected != block_hash:
            return False
        if not _check_pow(block_hash, difficulty):
            return False
        hashes = [tx_hashes_raw[i:i+32] for i in range(0, len(tx_hashes_raw), 32)]
        if _txs_hash(hashes) != txs_hash:
            return False
        return True

    def _apply_block(self, block: Block) -> None:
        if block.block_hash in self._seen_blocks:
            return
        self._seen_blocks.add(block.block_hash)

        parent = self.chain.get(block.height - 1)
        parent_ok = block.height == 0 or (parent is not None and parent.block_hash == block.prev_hash)
        extends_tip = block.prev_hash == self.tip.block_hash
        longer_chain = block.height > self.tip.height and parent_ok

        if extends_tip or longer_chain:
            self.chain[block.height] = block  # only write canonical blocks
            old_tip = self.tip
            self.tip = block
            # re-add txs from orphaned blocks back to mempool
            if longer_chain and old_tip.block_hash != block.prev_hash:
                for h in range(block.height - 1, old_tip.height + 1):
                    orphan = self.chain.get(h)
                    if orphan:
                        for tx in orphan.txs:
                            if tx.hash not in self._mempool_hashes:
                                self.mempool.append(tx)
                                self._mempool_hashes.add(tx.hash)
            # remove txs confirmed in this block (works for both mined and received blocks)
            confirmed: set[bytes] = (
                {tx.hash for tx in block.txs} if block.txs
                else {block.raw_tx_hashes[i:i+32] for i in range(0, len(block.raw_tx_hashes), 32)}
            )
            self.mempool = [tx for tx in self.mempool if tx.hash not in confirmed]
            self._mempool_hashes -= confirmed
            self._restart_mining()
            # apply any future blocks already stored during gap recovery
            next_block = self.chain.get(block.height + 1)
            if next_block and next_block.block_hash not in self._seen_blocks:
                self._apply_block(next_block)
        ann = AnnounceBlock(
            block.height, block.prev_hash, block.txs_hash,
            block.timestamp, block.difficulty, block.nonce,
            block.block_hash, block.tx_hashes_bytes,
        )
        for peer in self._peers():
            self.ez_send(peer, ann)

    def _try_apply_payload(self, peer: Peer, height, prev_hash, txs_hash, timestamp, difficulty, nonce, block_hash, tx_hashes_raw) -> None:
        if block_hash in self._seen_blocks:
            return
        if not self._validate_block_payload(height, prev_hash, txs_hash, timestamp, difficulty, nonce, block_hash, tx_hashes_raw):
            return
        block = Block(height, prev_hash, txs_hash, timestamp, difficulty, nonce, block_hash, raw_tx_hashes=tx_hashes_raw)
        if height > 1:
            parent = self.chain.get(height - 1)
            if parent is None:
                self.chain[height] = block  # store for later when missing blocks arrive
                for h in range(self.tip.height + 1, height):
                    self.ez_send(peer, GetBlock(h))
                return
            if parent.block_hash != prev_hash:
                return
        self._apply_block(block)

    @lazy_wrapper(SubmitTransaction)
    def on_submit_transaction(self, peer: Peer, payload: SubmitTransaction) -> None:
        tx = Tx(payload.sender_key, payload.data, payload.timestamp, payload.signature)
        h = tx.hash
        try:
            key = default_eccrypto.key_from_public_bin(payload.sender_key)
            msg = payload.sender_key + payload.data + struct.pack(">q", payload.timestamp)
            valid = default_eccrypto.is_valid_signature(key, msg, payload.signature)
        except Exception:
            valid = False
        if not valid:
            self.ez_send(peer, SubmitTransactionResponse(False, b"", "Invalid signature"))
            return
        if h not in self._mempool_hashes:
            print(f"[TX] Received transaction {h.hex()[:12]} from server")
            self.mempool.append(tx)
            self._mempool_hashes.add(h)
            ann = AnnounceTransaction(payload.sender_key, payload.data, payload.timestamp, payload.signature)
            for p in self._peers():
                if p != peer:
                    self.ez_send(p, ann)
        self.ez_send(peer, SubmitTransactionResponse(True, h, "Accepted"))

    @lazy_wrapper(GetChainHeight)
    def on_get_chain_height(self, peer: Peer, payload: GetChainHeight) -> None:
        self.ez_send(peer, ChainHeightResponse(payload.request_id, self.tip.height, self.tip.block_hash))

    @lazy_wrapper(GetBlock)
    def on_get_block(self, peer: Peer, payload: GetBlock) -> None:
        block = self.chain.get(payload.height)
        if block is None:
            return
        self.ez_send(peer, BlockResponse(
            block.height, block.prev_hash, block.txs_hash,
            block.timestamp, block.difficulty, block.nonce,
            block.block_hash, block.tx_hashes_bytes,
        ))

    @lazy_wrapper(BlockResponse)
    def on_block_response(self, peer: Peer, payload: BlockResponse) -> None:
        self._try_apply_payload(peer, payload.height, payload.prev_hash, payload.txs_hash,
                                payload.timestamp, payload.difficulty, payload.nonce,
                                payload.block_hash, payload.tx_hashes)

    @lazy_wrapper(AnnounceBlock)
    def on_announce_block(self, peer: Peer, payload: AnnounceBlock) -> None:
        self._try_apply_payload(peer, payload.height, payload.prev_hash, payload.txs_hash,
                                payload.timestamp, payload.difficulty, payload.nonce,
                                payload.block_hash, payload.tx_hashes)

    @lazy_wrapper(AnnounceTransaction)
    def on_announce_transaction(self, _peer: Peer, payload: AnnounceTransaction) -> None:
        tx = Tx(payload.sender_key, payload.data, payload.timestamp, payload.signature)
        h = tx.hash
        if h not in self._mempool_hashes:
            self.mempool.append(tx)
            self._mempool_hashes.add(h)


# Runner helpers

def load_members() -> dict:
    member = {}
    for file in os.listdir("keys"):
        with open(os.path.join("keys", file), "rb") as f:
            key = default_eccrypto.key_from_private_bin(f.read())
            member[file.replace(".pem", "")] = key.pub().key_to_bin()
    with open("my_key.pem", "rb") as f:
        key = default_eccrypto.key_from_private_bin(f.read())
        member["adithya"] = key.pub().key_to_bin()
    return member


def _make_ipv8(key_file: str, port: int, member: dict) -> IPv8:
    builder = (
        ConfigBuilder()
        .clear_keys()
        .clear_overlays()
        .add_key("my_key", "curve25519", key_file)
        .add_overlay(
            "RegistrationCommunity", "my_key",
            [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 3.0})],
            default_bootstrap_defs, {}, [],
        )
        .add_overlay(
            "BlockchainCommunity", "my_key",
            [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 3.0})],
            default_bootstrap_defs,
            {"member_1": member["adithya"], "member_2": member["dyujoy"], "member_3": member["sadi"]},
            [("started",)],
        )
    )
    config = builder.finalize()
    config["interfaces"][0]["port"] = port
    return IPv8(config, extra_communities={
        "RegistrationCommunity": RegistrationCommunity,
        "BlockchainCommunity": BlockchainCommunity,
    })


async def run_node(key_file: str, port: int, member: dict, is_registrar: bool = False) -> None:
    ipv8 = _make_ipv8(key_file, port, member)
    await ipv8.start()
    reg: RegistrationCommunity = ipv8.overlays[0]
    bc: BlockchainCommunity = ipv8.overlays[1]

    if is_registrar:
        print("[Net] Waiting for all member peers...")
        while len(bc._peers()) < 2:
            await asyncio.sleep(0.1)
        print("[Net] All peers found. Finding server...")
        while not reg._server():
            await asyncio.sleep(0.1)
        reg.register()

    try:
        await asyncio.sleep(400)
    finally:
        bc._mine_stop.set()
        await ipv8.stop()


