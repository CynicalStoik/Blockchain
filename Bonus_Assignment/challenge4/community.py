"""
Challenge 4 — Fork Convergence: IPv8 Community

Wraps blockchain.py with IPv8 peer-to-peer networking.

Key behaviours beyond a naive broadcast-and-apply node
───────────────────────────────────────────────────────
  • Competing tip tracking  — chain keeps ALL known branches; only the longest
                              becomes canonical, but alternatives are stored.
  • Bulk sync after partition  — on receiving a ChainHeightResponse that exceeds
                                 our tip, we call chain.missing_heights() and
                                 request every missing block from the peer.
  • Fork announcement       — whenever we apply a block that creates or extends a
                              non-canonical branch, we still broadcast the block so
                              peers can decide whether it beats their own canonical.
  • Out-of-order delivery   — if we receive a block whose parent we don't know, it
                              is stored in _pending (inside Chain) until the parent
                              arrives; we also proactively request the gap.
"""
from __future__ import annotations

import asyncio
import hashlib
import threading
import time

from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8_service import IPv8

from .blockchain import (
    Block, Tx, Chain,
    compute_block_hash, compute_txs_hash, check_pow,
    mine_worker, GENESIS, DIFFICULTY,
)

COMMUNITY_ID = hashlib.sha256(b"ForkConvergence_v1").digest()[:20]


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

@vp_compile
class AnnounceTip(VariablePayload):
    """Periodic gossip: share our current tip so peers know about forks."""
    msg_id = 7
    format_list = ["q", "varlenH"]
    names = ["height", "tip_hash"]


# ── Community ─────────────────────────────────────────────────────────────────

class ForkConvergenceCommunity(Community):
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
        self.add_message_handler(AnnounceTip, self.on_announce_tip)

    def started(self) -> None:
        self.register_task("mine_start", self._begin_mining, delay=2.0)
        # Periodically poll peers for their height (partition recovery)
        self.register_task("height_poll", self._poll_peers_height,
                           interval=10.0, delay=5.0)

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
                tip.block_hash, th, int(time.time()), DIFFICULTY, stop,
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
                print(f"[Chain] Mined block {block.height} "
                      f"hash={bh.hex()[:12]} "
                      f"tips={len(self.chain.tips)}")
                self._broadcast_block(block)
                self._broadcast_tip()
                self._restart_mining()

    # ── Broadcast helpers ─────────────────────────────────────────────────────

    def _broadcast_block(self, block: Block) -> None:
        ann = AnnounceBlock(block.height, block.prev_hash, block.txs_hash,
                            block.timestamp, block.difficulty, block.nonce,
                            block.block_hash, block.tx_hashes_bytes)
        for peer in self.get_peers():
            self.ez_send(peer, ann)

    def _broadcast_tip(self) -> None:
        tip = self.chain.tip
        for peer in self.get_peers():
            self.ez_send(peer, AnnounceTip(tip.height, tip.block_hash))

    def _try_apply_payload(self, peer: Peer, height, prev_hash, txs_hash,
                            timestamp, difficulty, nonce, block_hash,
                            tx_hashes_raw) -> bool:
        if block_hash in self.chain._seen:
            return False
        expected = compute_block_hash(prev_hash, txs_hash, timestamp, difficulty, nonce)
        if expected != block_hash or not check_pow(block_hash, difficulty):
            return False
        block = Block(height, prev_hash, txs_hash, timestamp, difficulty,
                      nonce, block_hash, raw_tx_hashes=tx_hashes_raw)
        applied = self.chain.apply_block(block)
        if applied:
            self._broadcast_block(block)
            self._restart_mining()
        elif height > self.chain.tip.height:
            # We might be behind — request the gap
            for h in self.chain.missing_heights(height):
                self.ez_send(peer, GetBlock(h))
        return applied

    # ── Periodic partition-recovery poll ──────────────────────────────────────

    async def _poll_peers_height(self) -> None:
        for peer in self.get_peers():
            self.ez_send(peer, GetChainHeight())

    # ── Message handlers ──────────────────────────────────────────────────────

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
        # Serve from canonical chain OR any stored fork block
        block = self.chain.canonical.get(p.height)
        if block is None:
            # Try stored non-canonical blocks at this height
            for (h, bh), b in self.chain.blocks.items():
                if h == p.height:
                    block = b
                    break
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
            for h in self.chain.missing_heights(p.height):
                self.ez_send(peer, GetBlock(h))

    @lazy_wrapper(AnnounceTip)
    def on_announce_tip(self, peer: Peer, p: AnnounceTip) -> None:
        if p.height > self.chain.tip.height:
            for h in self.chain.missing_heights(p.height):
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
            "ForkConvergenceCommunity", "my_key",
            [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 3.0})],
            default_bootstrap_defs, {}, [("started",)],
        )
    )
    config = builder.finalize()
    config["interfaces"][0]["port"] = port
    return IPv8(config, extra_communities={
        "ForkConvergenceCommunity": ForkConvergenceCommunity,
    })
