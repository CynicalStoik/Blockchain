"""
Challenge 5 — Adaptive Difficulty Blockchain
Pure blockchain logic with no IPv8 dependency.
Used by community.py (network layer) and tests alike.
"""
from __future__ import annotations

import hashlib
import math
import struct
import threading
import time
from dataclasses import dataclass, field

# Difficulty parameters
TARGET_BLOCK_TIME: float = 1.0   # seconds per block
DIFFICULTY_WINDOW: int = 10      # blocks looked back for adjustment
INITIAL_DIFFICULTY: int = 16     # bits at chain start
MIN_DIFFICULTY: int = 4
MAX_DIFFICULTY: int = 48

EMPTY_TXSHASH = hashlib.sha256(b"").digest()


# ── Primitives ────────────────────────────────────────────────────────────────

def pack_header(prev_hash: bytes, txs_hash: bytes, timestamp: int,
                difficulty: int, nonce: int) -> bytes:
    return (prev_hash + txs_hash
            + struct.pack(">Q", timestamp)
            + struct.pack(">I", difficulty)
            + struct.pack(">Q", nonce))


def compute_block_hash(prev_hash: bytes, txs_hash: bytes, timestamp: int,
                       difficulty: int, nonce: int) -> bytes:
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


# ── Adaptive difficulty ───────────────────────────────────────────────────────

def next_difficulty(chain: dict[int, Block], tip: Block) -> int:
    """
    Compute the required difficulty for the block that extends *tip*.

    Algorithm: look at the last DIFFICULTY_WINDOW blocks, compare their
    actual wall-clock span to DIFFICULTY_WINDOW * TARGET_BLOCK_TIME, then
    adjust the current difficulty by log2(target/actual) bits — equivalent
    to a multiplicative rescaling of the expected work.

    Clamped to [MIN_DIFFICULTY, MAX_DIFFICULTY] so a single rogue timestamp
    can never swing difficulty to an extreme.
    """
    if tip.height == 0:
        return INITIAL_DIFFICULTY
    # Skip adjustment until we have DIFFICULTY_WINDOW complete inter-block
    # intervals above genesis (genesis.timestamp=0 pollutes the window).
    if tip.height <= DIFFICULTY_WINDOW:
        return tip.difficulty if tip.difficulty > 0 else INITIAL_DIFFICULTY

    window_start = chain.get(tip.height - DIFFICULTY_WINDOW)
    if window_start is None:
        return tip.difficulty

    elapsed = tip.timestamp - window_start.timestamp
    if elapsed <= 0:
        elapsed = 1  # guard against identical timestamps in tests

    actual_avg = elapsed / DIFFICULTY_WINDOW
    # +1 bit ≈ 2× harder, so we add log2(target/actual) to current difficulty
    delta = math.log2(TARGET_BLOCK_TIME / actual_avg)
    new_diff = tip.difficulty + round(delta)
    return max(MIN_DIFFICULTY, min(MAX_DIFFICULTY, new_diff))


# ── Mining helpers ────────────────────────────────────────────────────────────

def mine_worker(prev_hash: bytes, th: bytes, timestamp: int,
                difficulty: int, stop: threading.Event) -> tuple[int, int] | None:
    """CPU-bound worker — runs in a thread/executor."""
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


def mine_block(chain: dict[int, Block], tip: Block,
               txs: list[Tx] | None = None,
               stop: threading.Event | None = None) -> Block | None:
    """Mine the next block that extends *tip* using adaptive difficulty."""
    if txs is None:
        txs = []
    if stop is None:
        stop = threading.Event()
    diff = next_difficulty(chain, tip)
    th = compute_txs_hash([tx.hash for tx in txs])
    result = mine_worker(tip.block_hash, th, int(time.time()), diff, stop)
    if result is None:
        return None
    nonce, ts = result
    bh = compute_block_hash(tip.block_hash, th, ts, diff, nonce)
    return Block(height=tip.height + 1, prev_hash=tip.block_hash,
                 txs_hash=th, timestamp=ts, difficulty=diff,
                 nonce=nonce, block_hash=bh, txs=txs)


def mine_block_at_time(tip: Block, txs: list[Tx],
                       difficulty: int, timestamp: int) -> Block:
    """
    Mine a block at a *fixed* timestamp — used in tests to control apparent
    mining rate without waiting for wall-clock time to advance.
    """
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


# ── Validation ────────────────────────────────────────────────────────────────

def validate_block(chain: dict[int, Block], block: Block) -> str | None:
    """
    Validate *block* against *chain*.  Returns None on success or an error
    string describing the first failing check.
    """
    expected_hash = compute_block_hash(
        block.prev_hash, block.txs_hash,
        block.timestamp, block.difficulty, block.nonce,
    )
    if expected_hash != block.block_hash:
        return "hash mismatch"
    if not check_pow(block.block_hash, block.difficulty):
        return "PoW not satisfied"

    if block.height > 0:
        parent = chain.get(block.height - 1)
        if parent is None:
            return "parent not in chain"
        if parent.block_hash != block.prev_hash:
            return "prev_hash mismatch"
        expected_diff = next_difficulty(chain, parent)
        if block.difficulty != expected_diff:
            return (f"wrong difficulty: got {block.difficulty}, "
                    f"expected {expected_diff}")

    hashes: list[bytes] = (
        [tx.hash for tx in block.txs] if block.txs
        else [block.raw_tx_hashes[i:i + 32]
              for i in range(0, len(block.raw_tx_hashes), 32)]
    )
    if compute_txs_hash(hashes) != block.txs_hash:
        return "txs_hash mismatch"

    return None  # all good


# ── Chain state ───────────────────────────────────────────────────────────────

class Chain:
    """
    Lightweight chain state used by both community.py and tests.
    Tracks the canonical tip and block dict; handles fork resolution.

    ``blocks``     — canonical chain: height → Block.
    ``_all_blocks``— all known blocks (including forks): block_hash → Block.
                     Parent lookups use this so fork branches are never lost.
    """

    def __init__(self) -> None:
        self.blocks: dict[int, Block] = {0: GENESIS}
        self._all_blocks: dict[bytes, Block] = {GENESIS.block_hash: GENESIS}
        self.tip: Block = GENESIS
        self.mempool: list[Tx] = []
        self._mempool_hashes: set[bytes] = set()
        self._seen: set[bytes] = {GENESIS.block_hash}

    def add_tx(self, tx: Tx) -> bool:
        if tx.hash in self._mempool_hashes:
            return False
        self.mempool.append(tx)
        self._mempool_hashes.add(tx.hash)
        return True

    def apply_block(self, block: Block) -> bool:
        """
        Try to apply *block*.  Returns True if the block extended or
        replaced the canonical tip.
        """
        if block.block_hash in self._seen:
            return False

        # Parent must be a known block (on any branch, not just canonical)
        if block.height > 0 and block.prev_hash not in self._all_blocks:
            return False

        self._seen.add(block.block_hash)
        self._all_blocks[block.block_hash] = block

        if block.height <= self.tip.height:
            # Store the block for future reorg potential but don't switch yet
            return False

        # This block extends beyond our current tip — switch canonical chain
        return self._reorg_to(block)

    def _reorg_to(self, new_tip: Block) -> bool:
        """Walk back from new_tip through _all_blocks to rebuild canonical."""
        new_chain: dict[int, Block] = {}
        cur: Block | None = new_tip
        while cur is not None and cur.height > 0:
            new_chain[cur.height] = cur
            cur = self._all_blocks.get(cur.prev_hash)
        new_chain[0] = GENESIS

        # Recover txs from orphaned canonical blocks
        new_hashes = {b.block_hash for b in new_chain.values()}
        for b in self.blocks.values():
            if b.block_hash not in new_hashes:
                for tx in (b.txs or []):
                    self.add_tx(tx)

        self.blocks = new_chain
        self.tip = new_tip

        # Remove txs now confirmed in the new canonical chain
        all_confirmed: set[bytes] = {
            tx.hash for b in new_chain.values() for tx in (b.txs or [])
        }
        self.mempool = [tx for tx in self.mempool if tx.hash not in all_confirmed]
        self._mempool_hashes -= all_confirmed
        return True
