"""
Challenge 0 — Big Block Transfer: IPv8 Community

Wraps challenge4's blockchain with the sliding-window transport layer so
that blocks too large for a single UDP datagram can be reliably exchanged.

Protocol
────────
  Small block (≤ LARGE_BLOCK_THRESHOLD bytes serialised):
    Sender  → AnnounceBlock   (full data, one packet)
    Peers   apply immediately

  Large block (> LARGE_BLOCK_THRESHOLD bytes):
    Miner   → LargeBlockRef   (height + block_hash only)
    Peers   → RequestLargeBlock (block_hash)
    Miner   starts TransportManager.start_send() with serialised block bytes
    Peers   receive TransferInit / DataChunk / SelectiveAck / TransferDone
            via their message handlers, which delegate to TransportManager
    On reassembly: deserialise and apply to Chain

  All peers also exchange ChainHeightResponse on GetChainHeight for bulk sync
  after a network partition heals.
"""
from __future__ import annotations

import asyncio
import hashlib
import struct
import threading
import time
from dataclasses import dataclass

from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8_service import IPv8

# Reuse challenge4's battle-tested blockchain (fork convergence included)
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from challenge4.blockchain import (
    Block, Tx, Chain,
    compute_block_hash, compute_txs_hash, check_pow,
    mine_worker, GENESIS, DIFFICULTY, pack_header,
)
from .transport import TransportManager, TransferInit, DataChunk, SelectiveAck, TransferDone

COMMUNITY_ID = hashlib.sha256(b"BigBlockTransfer_v1").digest()[:20]

# Blocks smaller than this are sent inline; larger blocks use the transport.
LARGE_BLOCK_THRESHOLD = 800   # bytes


# ── Block serialisation helpers ───────────────────────────────────────────────

def serialise_tx(tx: Tx) -> bytes:
    """key(32) | data_len(2) | data | ts(8) | sig(64)"""
    d = tx.data
    return (tx.sender_key
            + struct.pack(">H", len(d)) + d
            + struct.pack(">q", tx.timestamp)
            + tx.signature)


def serialise_block(block: Block) -> bytes:
    """header(84) | n_txs(4) | [serialised_tx]*"""
    header = pack_header(block.prev_hash, block.txs_hash,
                         block.timestamp, block.difficulty, block.nonce)
    txs_bytes = b"".join(serialise_tx(tx) for tx in (block.txs or []))
    return (block.block_hash        # 32 bytes — so receiver can verify immediately
            + struct.pack(">I", block.height)
            + header
            + struct.pack(">I", len(block.txs or []))
            + txs_bytes)


def deserialise_block(data: bytes) -> Block | None:
    try:
        block_hash = data[:32]
        height = struct.unpack(">I", data[32:36])[0]
        off = 36
        prev_hash = data[off:off + 32]; off += 32
        txs_hash  = data[off:off + 32]; off += 32
        timestamp = struct.unpack(">Q", data[off:off + 8])[0]; off += 8
        difficulty = struct.unpack(">I", data[off:off + 4])[0]; off += 4
        nonce = struct.unpack(">Q", data[off:off + 8])[0]; off += 8
        n_txs = struct.unpack(">I", data[off:off + 4])[0]; off += 4
        txs: list[Tx] = []
        for _ in range(n_txs):
            key = data[off:off + 32]; off += 32
            dlen = struct.unpack(">H", data[off:off + 2])[0]; off += 2
            tx_data = data[off:off + dlen]; off += dlen
            ts = struct.unpack(">q", data[off:off + 8])[0]; off += 8
            sig = data[off:off + 64]; off += 64
            txs.append(Tx(key, tx_data, ts, sig))
        return Block(height=height, prev_hash=prev_hash, txs_hash=txs_hash,
                     timestamp=timestamp, difficulty=difficulty, nonce=nonce,
                     block_hash=block_hash, txs=txs)
    except Exception:
        return None


# ── Payloads ──────────────────────────────────────────────────────────────────

@vp_compile
class AnnounceBlock(VariablePayload):
    msg_id = 1
    format_list = ["q", "varlenH", "varlenH", "q", "q", "q", "varlenH"]
    names = ["height", "prev_hash", "txs_hash", "timestamp", "difficulty",
             "nonce", "block_hash"]

@vp_compile
class GetBlock(VariablePayload):
    msg_id = 2
    format_list = ["q"]
    names = ["height"]

@vp_compile
class BlockResponse(VariablePayload):
    msg_id = 3
    format_list = ["q", "varlenH", "varlenH", "q", "q", "q", "varlenH"]
    names = ["height", "prev_hash", "txs_hash", "timestamp", "difficulty",
             "nonce", "block_hash"]

@vp_compile
class GetChainHeight(VariablePayload):
    msg_id = 4
    format_list = []
    names = []

@vp_compile
class ChainHeightResponse(VariablePayload):
    msg_id = 5
    format_list = ["q", "varlenH"]
    names = ["height", "tip_hash"]

@vp_compile
class LargeBlockRef(VariablePayload):
    """Announce that a large block exists — receiver requests transfer."""
    msg_id = 6
    format_list = ["q", "varlenH"]
    names = ["height", "block_hash"]

@vp_compile
class RequestLargeBlock(VariablePayload):
    """Receiver requests the large block bytes via the transport layer."""
    msg_id = 7
    format_list = ["varlenH"]
    names = ["block_hash"]

# Transport wire payloads
@vp_compile
class WireTransferInit(VariablePayload):
    msg_id = 10
    format_list = ["varlenH", "q", "q", "q"]
    names = ["transfer_id", "total_bytes", "chunk_size", "num_chunks"]

@vp_compile
class WireDataChunk(VariablePayload):
    msg_id = 11
    format_list = ["varlenH", "q", "varlenH"]
    names = ["transfer_id", "seq", "data"]

@vp_compile
class WireSelectiveAck(VariablePayload):
    msg_id = 12
    format_list = ["varlenH", "q", "varlenH"]
    names = ["transfer_id", "base", "bitmap"]

@vp_compile
class WireTransferDone(VariablePayload):
    msg_id = 13
    format_list = ["varlenH"]
    names = ["transfer_id"]


# ── Community ─────────────────────────────────────────────────────────────────

class BigBlockCommunity(Community):
    community_id = COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.chain = Chain()
        self._mine_stop = threading.Event()
        self._mine_task: asyncio.Task | None = None
        # block_hash → Block for large blocks we've mined (to serve requests)
        self._large_block_cache: dict[bytes, Block] = {}

        # Transport layer: send_fn bridges TransportManager → IPv8
        self._transport = TransportManager(
            send_fn=self._transport_send,
            on_complete=self._on_large_block_received,
        )

        self.add_message_handler(AnnounceBlock, self.on_announce_block)
        self.add_message_handler(GetBlock, self.on_get_block)
        self.add_message_handler(BlockResponse, self.on_block_response)
        self.add_message_handler(GetChainHeight, self.on_get_chain_height)
        self.add_message_handler(ChainHeightResponse, self.on_chain_height_response)
        self.add_message_handler(LargeBlockRef, self.on_large_block_ref)
        self.add_message_handler(RequestLargeBlock, self.on_request_large_block)
        self.add_message_handler(WireTransferInit, self.on_wire_transfer_init)
        self.add_message_handler(WireDataChunk, self.on_wire_data_chunk)
        self.add_message_handler(WireSelectiveAck, self.on_wire_sack)
        self.add_message_handler(WireTransferDone, self.on_wire_transfer_done)

    def started(self) -> None:
        self._transport.start()
        self.register_task("mine_start", self._begin_mining, delay=2.0)

    async def _begin_mining(self) -> None:
        self._restart_mining()

    # ── Mining ────────────────────────────────────────────────────────────────

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
            tip = self.chain.tip
            pending = list(self.chain.mempool)
            th = compute_txs_hash([tx.hash for tx in pending])
            result = await loop.run_in_executor(
                None, mine_worker,
                tip.block_hash, th,
                int(time.time()), DIFFICULTY, stop,
            )
            if result is None or stop.is_set():
                continue
            nonce, ts = result
            if self.chain.tip.block_hash != tip.block_hash:
                continue
            bh = compute_block_hash(tip.block_hash, th, ts, DIFFICULTY, nonce)
            block = Block(height=tip.height + 1, prev_hash=tip.block_hash,
                          txs_hash=th, timestamp=ts, difficulty=DIFFICULTY,
                          nonce=nonce, block_hash=bh, txs=pending)
            if self.chain.apply_block(block):
                print(f"[Chain] Mined block {block.height} hash={bh.hex()[:12]}")
                self._announce_block(block)
                self._restart_mining()

    # ── Block announcement ────────────────────────────────────────────────────

    def _announce_block(self, block: Block) -> None:
        raw = serialise_block(block)
        if len(raw) <= LARGE_BLOCK_THRESHOLD:
            ann = AnnounceBlock(block.height, block.prev_hash, block.txs_hash,
                                block.timestamp, block.difficulty, block.nonce,
                                block.block_hash)
            for peer in self.get_peers():
                self.ez_send(peer, ann)
        else:
            # Too large: cache it and broadcast a reference
            self._large_block_cache[block.block_hash] = block
            ref = LargeBlockRef(block.height, block.block_hash)
            for peer in self.get_peers():
                self.ez_send(peer, ref)

    # ── Transport bridge ──────────────────────────────────────────────────────

    # _peer_for_send is set temporarily during send so that _transport_send
    # knows which peer to route to.  TransportManager calls _transport_send
    # synchronously from within start_send / on_ack.
    _current_send_peer: Peer | None = None

    def _transport_send(self, peer: Peer, msg: object) -> None:
        """Route a transport wire object to an IPv8 payload and send it."""
        if isinstance(msg, TransferInit):
            self.ez_send(peer, WireTransferInit(
                msg.transfer_id, msg.total_bytes, msg.chunk_size, msg.num_chunks))
        elif isinstance(msg, DataChunk):
            self.ez_send(peer, WireDataChunk(msg.transfer_id, msg.seq, msg.data))
        elif isinstance(msg, SelectiveAck):
            self.ez_send(peer, WireSelectiveAck(msg.transfer_id, msg.base, msg.bitmap))
        elif isinstance(msg, TransferDone):
            self.ez_send(peer, WireTransferDone(msg.transfer_id))

    async def _on_large_block_received(self, peer: Peer, data: bytes) -> None:
        block = deserialise_block(data)
        if block is None:
            return
        if self.chain.apply_block(block):
            print(f"[Chain] Applied large block {block.height} "
                  f"hash={block.block_hash.hex()[:12]} "
                  f"({len(data)} bytes via transport)")
            self._announce_block(block)
            self._restart_mining()

    # ── Message handlers ──────────────────────────────────────────────────────

    @lazy_wrapper(AnnounceBlock)
    def on_announce_block(self, peer: Peer, p: AnnounceBlock) -> None:
        if p.block_hash in self.chain._seen:
            return
        expected = compute_block_hash(p.prev_hash, p.txs_hash, p.timestamp,
                                      p.difficulty, p.nonce)
        if expected != p.block_hash or not check_pow(p.block_hash, p.difficulty):
            return
        block = Block(height=p.height, prev_hash=p.prev_hash,
                      txs_hash=p.txs_hash, timestamp=p.timestamp,
                      difficulty=p.difficulty, nonce=p.nonce,
                      block_hash=p.block_hash, txs=[])
        if self.chain.apply_block(block):
            self._announce_block(block)
            self._restart_mining()
        elif p.height > self.chain.tip.height + 1:
            for h in range(self.chain.tip.height + 1, p.height):
                self.ez_send(peer, GetBlock(h))

    @lazy_wrapper(GetBlock)
    def on_get_block(self, peer: Peer, p: GetBlock) -> None:
        block = self.chain.canonical.get(p.height)
        if block:
            self.ez_send(peer, BlockResponse(
                block.height, block.prev_hash, block.txs_hash,
                block.timestamp, block.difficulty, block.nonce,
                block.block_hash))

    @lazy_wrapper(BlockResponse)
    def on_block_response(self, peer: Peer, p: BlockResponse) -> None:
        self.on_announce_block.__wrapped__(self, peer, p)  # type: ignore[attr-defined]

    @lazy_wrapper(GetChainHeight)
    def on_get_chain_height(self, peer: Peer, _p: GetChainHeight) -> None:
        tip = self.chain.tip
        self.ez_send(peer, ChainHeightResponse(tip.height, tip.block_hash))

    @lazy_wrapper(ChainHeightResponse)
    def on_chain_height_response(self, peer: Peer, p: ChainHeightResponse) -> None:
        for h in self.chain.missing_heights(p.height):
            self.ez_send(peer, GetBlock(h))

    @lazy_wrapper(LargeBlockRef)
    def on_large_block_ref(self, peer: Peer, p: LargeBlockRef) -> None:
        if p.block_hash not in self.chain._seen:
            self.ez_send(peer, RequestLargeBlock(p.block_hash))

    @lazy_wrapper(RequestLargeBlock)
    def on_request_large_block(self, peer: Peer, p: RequestLargeBlock) -> None:
        block = self._large_block_cache.get(p.block_hash)
        if block is None:
            # Try canonical chain
            for b in self.chain.canonical.values():
                if b.block_hash == p.block_hash:
                    block = b
                    break
        if block:
            data = serialise_block(block)
            self._transport.start_send(peer, data)

    @lazy_wrapper(WireTransferInit)
    def on_wire_transfer_init(self, peer: Peer, p: WireTransferInit) -> None:
        self._transport.on_init(peer, TransferInit(
            p.transfer_id, p.total_bytes, p.chunk_size, p.num_chunks))

    @lazy_wrapper(WireDataChunk)
    def on_wire_data_chunk(self, peer: Peer, p: WireDataChunk) -> None:
        self._transport.on_chunk(peer, DataChunk(p.transfer_id, p.seq, p.data))

    @lazy_wrapper(WireSelectiveAck)
    def on_wire_sack(self, peer: Peer, p: WireSelectiveAck) -> None:
        self._transport.on_ack(peer, SelectiveAck(p.transfer_id, p.base, p.bitmap))

    @lazy_wrapper(WireTransferDone)
    def on_wire_transfer_done(self, peer: Peer, p: WireTransferDone) -> None:
        self._transport.on_done(peer, TransferDone(p.transfer_id))


# ── Runner helper ─────────────────────────────────────────────────────────────

def make_ipv8(key_file: str, port: int) -> IPv8:
    builder = (
        ConfigBuilder()
        .clear_keys()
        .clear_overlays()
        .add_key("my_key", "curve25519", key_file)
        .add_overlay(
            "BigBlockCommunity", "my_key",
            [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 3.0})],
            default_bootstrap_defs, {}, [("started",)],
        )
    )
    config = builder.finalize()
    config["interfaces"][0]["port"] = port
    return IPv8(config, extra_communities={"BigBlockCommunity": BigBlockCommunity})
