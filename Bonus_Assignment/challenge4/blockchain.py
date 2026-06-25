"""
Challenge 4 — Fork Convergence Blockchain
Pure blockchain logic with no IPv8 dependency.

Key additions over a naive chain:
  • Competing tip tracking  — know every live branch, not just the longest.
  • Atomic reorg            — switch canonical chain in one step; never expose
                              a partial state.
  • Orphan tx recovery      — on reorg, every tx that was confirmed in the
                              orphaned branch but is absent from the new
                              canonical branch goes back into the mempool.
  • Reorg depth limit       — refuse a reorg deeper than MAX_REORG_DEPTH so
                              a long-range attack cannot roll back the chain
                              arbitrarily far.
  • Bulk sync support       — callers can query missing_heights() to learn
                              which block heights they need to request from
                              peers after a partition heals.
"""
from __future__ import annotations

import hashlib
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

DIFFICULTY = 16           # fixed difficulty (adaptive difficulty is challenge 5)
MAX_REORG_DEPTH = 100     # refuse reorgs deeper than this
EMPTY_TXSHASH = hashlib.sha256(b"").digest()


# ── Primitives ────────────────────────────────────────────────────────────────

def pack_header(prev_hash: bytes, txs_hash: bytes,
                timestamp: int, difficulty: int, nonce: int) -> bytes:
    return (prev_hash + txs_hash
            + struct.pack(">Q", timestamp)
            + struct.pack(">I", difficulty)
            + struct.pack(">Q", nonce))


def compute_block_hash(prev_hash: bytes, txs_hash: bytes,
                       timestamp: int, difficulty: int, nonce: int) -> bytes:
    return hashlib.sha256(
        pack_header(prev_hash, txs_hash, timestamp, difficulty, nonce)
    ).digest()


def check_pow(h: bytes, difficulty: int) -> bool:
    full, rem = divmod(difficulty, 8)
    for i in range(full):
        if h[i] != 0:
            return False
    if rem and h[full] >= (1 << (8 - rem)):
        return False
    return True


def compute_tx_hash(sender_key: bytes, data: bytes,
                    timestamp: int, signature: bytes) -> bytes:
    return hashlib.sha256(
        sender_key + data + struct.pack(">q", timestamp) + signature
    ).digest()


def compute_txs_hash(hashes: list[bytes]) -> bytes:
    return hashlib.sha256(b"".join(hashes)).digest() if hashes else EMPTY_TXSHASH


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class Tx:
    sender_key: bytes
    data: bytes
    timestamp: int
    signature: bytes

    @property
    def hash(self) -> bytes:
        return compute_tx_hash(self.sender_key, self.data,
                               self.timestamp, self.signature)


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


def make_genesis() -> Block:
    ph = b"\x00" * 32
    th = EMPTY_TXSHASH
    bh = compute_block_hash(ph, th, 0, 0, 0)
    return Block(height=0, prev_hash=ph, txs_hash=th,
                 timestamp=0, difficulty=0, nonce=0, block_hash=bh)


GENESIS = make_genesis()


# ── Mining helper ─────────────────────────────────────────────────────────────

def mine_block_at_time(tip: Block, txs: list[Tx],
                       difficulty: int, timestamp: int) -> Block:
    """Mine a block at a fixed timestamp (for tests and deterministic chains)."""
    th = compute_txs_hash([tx.hash for tx in txs])
    nonce = 0
    while True:
        h = hashlib.sha256(
            pack_header(tip.block_hash, th, timestamp, difficulty, nonce)
        ).digest()
        if check_pow(h, difficulty):
            return Block(height=tip.height + 1, prev_hash=tip.block_hash,
                         txs_hash=th, timestamp=timestamp,
                         difficulty=difficulty, nonce=nonce, block_hash=h,
                         txs=txs)
        nonce += 1


def mine_worker(prev_hash: bytes, th: bytes, timestamp: int,
                difficulty: int, stop: threading.Event) -> tuple[int, int] | None:
    nonce = 0
    ts = timestamp
    while not stop.is_set():
        h = hashlib.sha256(
            pack_header(prev_hash, th, ts, difficulty, nonce)
        ).digest()
        if check_pow(h, difficulty):
            return nonce, ts
        nonce += 1
        if nonce % 10_000 == 0:
            ts = int(time.time())
    return None


# ── Chain state with fork convergence ────────────────────────────────────────

class Chain:
    """
    Full chain state with competing-tip tracking and atomic reorgs.

    Design notes
    ------------
    ``blocks``   — all blocks ever accepted (canonical + known forks),
                   keyed by (height, block_hash) so two blocks at the same
                   height can coexist.
    ``canonical``— height → block for the canonical chain only.
    ``tips``     — set of block_hashes that are not yet extended by any
                   known block; each is a potential chain head.
    ``tip``      — the canonical tip (highest / heaviest branch).
    """

    def __init__(self) -> None:
        self.blocks: dict[tuple[int, bytes], Block] = {
            (0, GENESIS.block_hash): GENESIS,
        }
        self.canonical: dict[int, Block] = {0: GENESIS}
        self.tips: set[bytes] = {GENESIS.block_hash}
        self.tip: Block = GENESIS
        self.mempool: list[Tx] = []
        self._mempool_hashes: set[bytes] = set()
        self._seen: set[bytes] = {GENESIS.block_hash}
        # pending blocks whose parent we haven't seen yet
        self._pending: dict[bytes, Block] = {}  # prev_hash → block

    # ── Public API ────────────────────────────────────────────────────────────

    def add_tx(self, tx: Tx) -> bool:
        if tx.hash in self._mempool_hashes:
            return False
        self.mempool.append(tx)
        self._mempool_hashes.add(tx.hash)
        return True

    def apply_block(self, block: Block) -> bool:
        """
        Integrate *block* into the chain.

        Returns True if it extended or replaced the canonical tip.
        Returns False if the block was already known, invalid, or a rejected
        deep reorg.
        """
        if block.block_hash in self._seen:
            return False

        # Basic PoW validation
        expected = compute_block_hash(block.prev_hash, block.txs_hash,
                                      block.timestamp, block.difficulty,
                                      block.nonce)
        if expected != block.block_hash:
            return False
        if not check_pow(block.block_hash, block.difficulty):
            return False

        # Parent must be known (or this is genesis)
        parent = self._get_any_block(block.height - 1, block.prev_hash)
        if block.height > 0 and parent is None:
            # Store as pending; will be resolved once the parent arrives
            self._pending[block.prev_hash] = block
            return False

        # Reject reorgs deeper than MAX_REORG_DEPTH
        canonical_at_height = self.canonical.get(block.height)
        if (canonical_at_height is not None
                and canonical_at_height.block_hash != block.block_hash
                and self.tip.height - block.height >= MAX_REORG_DEPTH):
            return False

        self._seen.add(block.block_hash)
        self.blocks[(block.height, block.block_hash)] = block
        # Remove parent from tips set; add this block as a new tip
        self.tips.discard(block.prev_hash)
        self.tips.add(block.block_hash)

        changed = False
        if block.height > self.tip.height:
            changed = self._reorg_to(block)

        # Resolve any pending blocks whose parent is this block
        pending = self._pending.pop(block.block_hash, None)
        if pending is not None:
            self.apply_block(pending)

        return changed

    def missing_heights(self, peer_height: int) -> list[int]:
        """
        Return the list of block heights (in the canonical chain) that we do
        not yet have.  Used after a partition heals to bulk-request blocks.
        """
        return [h for h in range(self.tip.height + 1, peer_height + 1)
                if h not in self.canonical]

    def common_ancestor(self, other_tip: Block) -> Optional[Block]:
        """Walk back from *other_tip* until we find a block in our canonical chain."""
        cur: Block | None = other_tip
        while cur is not None:
            if cur.block_hash in {b.block_hash for b in self.canonical.values()}:
                return cur
            parent = self._get_any_block(cur.height - 1, cur.prev_hash)
            cur = parent
        return None

    # ── Internals ─────────────────────────────────────────────────────────────

    def _get_any_block(self, height: int, block_hash: bytes) -> Block | None:
        return self.blocks.get((height, block_hash))

    def _chain_from(self, tip: Block) -> list[Block]:
        """Walk back from *tip* through all known blocks to genesis."""
        chain: list[Block] = []
        cur: Block | None = tip
        while cur is not None and cur.height > 0:
            chain.append(cur)
            cur = self._get_any_block(cur.height - 1, cur.prev_hash)
        chain.reverse()
        return chain

    def _reorg_to(self, new_tip: Block) -> bool:
        """
        Atomically switch the canonical chain to the branch ending at *new_tip*.

        1. Walk back both the old and new branches to find their common ancestor.
        2. Collect orphaned txs (on the old branch above the ancestor but not
           on the new branch) and return them to the mempool.
        3. Rewrite ``canonical`` in one go.
        """
        old_tip = self.tip
        new_branch = self._chain_from(new_tip)
        old_branch = self._chain_from(old_tip)

        # Find common ancestor by comparing block hashes
        new_hashes = {b.block_hash for b in new_branch}
        old_branch_above_ancestor = [b for b in old_branch
                                      if b.block_hash not in new_hashes]
        new_branch_above_ancestor = [b for b in new_branch
                                      if b.block_hash not in
                                      {b2.block_hash for b2 in old_branch}]

        # Collect txs confirmed in old branch but absent from new branch
        new_confirmed = {tx.hash
                         for b in new_branch_above_ancestor
                         for tx in (b.txs or [])}
        for block in old_branch_above_ancestor:
            for tx in (block.txs or []):
                if tx.hash not in new_confirmed and tx.hash not in self._mempool_hashes:
                    self.mempool.append(tx)
                    self._mempool_hashes.add(tx.hash)

        # Atomic rewrite of canonical chain
        self.canonical = {0: GENESIS}
        for block in new_branch:
            self.canonical[block.height] = block
        self.canonical[new_tip.height] = new_tip
        self.tip = new_tip

        # Remove txs that are now confirmed in the new canonical chain
        all_confirmed = {tx.hash
                         for b in new_branch
                         for tx in (b.txs or [])}
        self.mempool = [tx for tx in self.mempool if tx.hash not in all_confirmed]
        self._mempool_hashes -= all_confirmed

        return True

    def validate_chain(self) -> list[str]:
        """
        Walk the canonical chain from genesis to tip and return a list of
        validation errors.  Empty list means the chain is valid.
        """
        errors: list[str] = []
        prev = GENESIS
        for h in range(1, self.tip.height + 1):
            block = self.canonical.get(h)
            if block is None:
                errors.append(f"missing canonical block at height {h}")
                continue
            if block.prev_hash != prev.block_hash:
                errors.append(f"height {h}: prev_hash mismatch")
            expected = compute_block_hash(block.prev_hash, block.txs_hash,
                                          block.timestamp, block.difficulty,
                                          block.nonce)
            if expected != block.block_hash:
                errors.append(f"height {h}: hash mismatch")
            if not check_pow(block.block_hash, block.difficulty):
                errors.append(f"height {h}: PoW not satisfied")
            prev = block
        return errors
