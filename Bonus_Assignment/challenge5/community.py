"""
Challenge 5 — Adaptive Difficulty: IPv8 Community
Wraps blockchain.py with IPv8 peer-to-peer networking.
"""
from __future__ import annotations

import asyncio
import hashlib
import struct
import threading

from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8_service import IPv8

from .blockchain import (
    Block, Tx, Chain,
    compute_block_hash, compute_txs_hash, check_pow,
    next_difficulty, mine_worker,
    GENESIS,
)

COMMUNITY_ID = hashlib.sha256(b"AdaptiveDifficulty_v1").digest()[:20]


# ── Payloads ──────────────────────────────────────────────────────────────────

@vp_compile
class AnnounceBlock(VariablePayload):
    msg_id = 1
    format_list = ["q", "varlenH", "varlenH", "q", "q", "q", "varlenH", "varlenH"]
    names = ["height", "prev_hash", "txs_hash", "timestamp", "difficulty", "nonce",
             "block_hash", "tx_hashes"]

@vp_compile
class GetBlock(VariablePayload):
    msg_id = 2
    format_list = ["q"]
    names = ["height"]

@vp_compile
class BlockResponse(VariablePayload):
    msg_id = 3
    format_list = ["q", "varlenH", "varlenH", "q", "q", "q", "varlenH", "varlenH"]
    names = ["height", "prev_hash", "txs_hash", "timestamp", "difficulty", "nonce",
             "block_hash", "tx_hashes"]

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
class AnnounceTransaction(VariablePayload):
    msg_id = 6
    format_list = ["varlenH", "varlenH", "q", "varlenH"]
    names = ["sender_key", "data", "timestamp", "signature"]


# ── Community ─────────────────────────────────────────────────────────────────

class AdaptiveDifficultyCommunity(Community):
    community_id = COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.chain = Chain()
        self._mine_stop = threading.Event()
        self._mine_task: asyncio.Task | None = None

        self.add_message_handler(AnnounceBlock, self.on_announce_block)
        self.add_message_handler(GetBlock, self.on_get_block)
        self.add_message_handler(BlockResponse, self.on_block_response)
        self.add_message_handler(GetChainHeight, self.on_get_chain_height)
        self.add_message_handler(ChainHeightResponse, self.on_chain_height_response)
        self.add_message_handler(AnnounceTransaction, self.on_announce_transaction)

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
            tip = self.chain.tip
            pending = list(self.chain.mempool)
            diff = next_difficulty(self.chain.blocks, tip)
            th = compute_txs_hash([tx.hash for tx in pending])
            result = await loop.run_in_executor(
                None, mine_worker, tip.block_hash, th,
                __import__("time").time_ns() // 1_000_000_000, diff, stop,
            )
            if result is None or stop.is_set():
                continue
            nonce, ts = result
            if self.chain.tip.block_hash != tip.block_hash:
                continue
            bh = compute_block_hash(tip.block_hash, th, ts, diff, nonce)
            block = Block(height=tip.height + 1, prev_hash=tip.block_hash,
                          txs_hash=th, timestamp=ts, difficulty=diff,
                          nonce=nonce, block_hash=bh, txs=pending)
            if self.chain.apply_block(block):
                print(f"[Chain] Mined block {block.height} diff={diff} "
                      f"hash={bh.hex()[:12]}")
                self._broadcast_block(block)
                self._restart_mining()

    def _broadcast_block(self, block: Block) -> None:
        ann = AnnounceBlock(block.height, block.prev_hash, block.txs_hash,
                            block.timestamp, block.difficulty, block.nonce,
                            block.block_hash, block.tx_hashes_bytes)
        for peer in self.get_peers():
            self.ez_send(peer, ann)

    def _try_apply_payload(self, peer: Peer, height, prev_hash, txs_hash,
                           timestamp, difficulty, nonce, block_hash,
                           tx_hashes_raw) -> None:
        if block_hash in self.chain._seen:
            return
        expected = compute_block_hash(prev_hash, txs_hash, timestamp, difficulty, nonce)
        if expected != block_hash or not check_pow(block_hash, difficulty):
            return
        hashes = [tx_hashes_raw[i:i + 32] for i in range(0, len(tx_hashes_raw), 32)]
        if compute_txs_hash(hashes) != txs_hash:
            return

        block = Block(height, prev_hash, txs_hash, timestamp, difficulty,
                      nonce, block_hash, raw_tx_hashes=tx_hashes_raw)

        if height > 1:
            parent = self.chain.blocks.get(height - 1)
            if parent is None:
                self.chain.blocks[height] = block
                for h in range(self.chain.tip.height + 1, height):
                    self.ez_send(peer, GetBlock(h))
                return
            if parent.block_hash != prev_hash:
                return
            expected_diff = next_difficulty(self.chain.blocks, parent)
            if difficulty != expected_diff:
                print(f"[Chain] Rejected block {height}: wrong diff "
                      f"(got {difficulty}, expected {expected_diff})")
                return

        if self.chain.apply_block(block):
            self._broadcast_block(block)
            self._restart_mining()
            next_b = self.chain.blocks.get(block.height + 1)
            if next_b and next_b.block_hash not in self.chain._seen:
                self._try_apply_payload(
                    peer, next_b.height, next_b.prev_hash, next_b.txs_hash,
                    next_b.timestamp, next_b.difficulty, next_b.nonce,
                    next_b.block_hash, next_b.raw_tx_hashes,
                )

    @lazy_wrapper(AnnounceBlock)
    def on_announce_block(self, peer: Peer, p: AnnounceBlock) -> None:
        self._try_apply_payload(peer, p.height, p.prev_hash, p.txs_hash,
                                p.timestamp, p.difficulty, p.nonce,
                                p.block_hash, p.tx_hashes)

    @lazy_wrapper(BlockResponse)
    def on_block_response(self, peer: Peer, p: BlockResponse) -> None:
        self._try_apply_payload(peer, p.height, p.prev_hash, p.txs_hash,
                                p.timestamp, p.difficulty, p.nonce,
                                p.block_hash, p.tx_hashes)

    @lazy_wrapper(GetBlock)
    def on_get_block(self, peer: Peer, p: GetBlock) -> None:
        block = self.chain.blocks.get(p.height)
        if block:
            self.ez_send(peer, BlockResponse(
                block.height, block.prev_hash, block.txs_hash,
                block.timestamp, block.difficulty, block.nonce,
                block.block_hash, block.tx_hashes_bytes,
            ))

    @lazy_wrapper(GetChainHeight)
    def on_get_chain_height(self, peer: Peer, _p: GetChainHeight) -> None:
        tip = self.chain.tip
        self.ez_send(peer, ChainHeightResponse(tip.height, tip.block_hash))

    @lazy_wrapper(ChainHeightResponse)
    def on_chain_height_response(self, peer: Peer, p: ChainHeightResponse) -> None:
        if p.height > self.chain.tip.height:
            for h in range(self.chain.tip.height + 1, p.height + 1):
                self.ez_send(peer, GetBlock(h))

    @lazy_wrapper(AnnounceTransaction)
    def on_announce_transaction(self, _peer: Peer, p: AnnounceTransaction) -> None:
        tx = Tx(p.sender_key, p.data, p.timestamp, p.signature)
        self.chain.add_tx(tx)


# ── Runner helper ─────────────────────────────────────────────────────────────

def make_ipv8(key_file: str, port: int) -> IPv8:
    builder = (
        ConfigBuilder()
        .clear_keys()
        .clear_overlays()
        .add_key("my_key", "curve25519", key_file)
        .add_overlay(
            "AdaptiveDifficultyCommunity", "my_key",
            [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 3.0})],
            default_bootstrap_defs, {}, [("started",)],
        )
    )
    config = builder.finalize()
    config["interfaces"][0]["port"] = port
    return IPv8(config, extra_communities={
        "AdaptiveDifficultyCommunity": AdaptiveDifficultyCommunity,
    })
