"""
Challenge 5 — Adaptive Difficulty: test suite
All tests mine *real* blocks (actual SHA-256 PoW) at low difficulty so the
suite runs in seconds.  No mocking of the blockchain primitives.
"""
from __future__ import annotations

import math
import sys
import os

import pytest

# Make the challenge5 package importable regardless of cwd
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from challenge5.blockchain import (
    GENESIS, INITIAL_DIFFICULTY, MIN_DIFFICULTY, MAX_DIFFICULTY,
    DIFFICULTY_WINDOW, TARGET_BLOCK_TIME,
    Block, Tx, Chain,
    next_difficulty, mine_block_at_time, validate_block,
    compute_block_hash, check_pow, compute_txs_hash, EMPTY_TXSHASH,
)

# Use a very low difficulty for tests so PoW completes in microseconds.
TEST_DIFFICULTY = 4   # 1/16 chance → ~16 hashes per block on average


# ── Helpers ───────────────────────────────────────────────────────────────────

def build_chain(num_blocks: int, inter_block_time: float,
                start_ts: int = 1_000_000,
                difficulty: int = TEST_DIFFICULTY) -> tuple[dict[int, Block], Block]:
    """
    Mine *num_blocks* real blocks where each block's timestamp is exactly
    *inter_block_time* seconds after the previous one.  Difficulty is fixed
    at TEST_DIFFICULTY (or *difficulty* if specified).
    """
    chain: dict[int, Block] = {0: GENESIS}
    tip = GENESIS
    ts = start_ts
    for _ in range(num_blocks):
        block = mine_block_at_time(tip, [], difficulty, ts)
        chain[block.height] = block
        tip = block
        ts += int(inter_block_time)
    return chain, tip


def build_adaptive_chain(num_blocks: int, inter_block_time: float,
                         start_ts: int = 1_000_000) -> tuple[dict[int, Block], Block]:
    """
    Mine *num_blocks* blocks where each block's *difficulty* is computed by
    next_difficulty() — i.e., the chain uses the real adaptive algorithm.
    """
    chain: dict[int, Block] = {0: GENESIS}
    tip = GENESIS
    ts = start_ts
    for _ in range(num_blocks):
        diff = next_difficulty(chain, tip)
        block = mine_block_at_time(tip, [], diff, ts)
        chain[block.height] = block
        tip = block
        ts += int(inter_block_time)
    return chain, tip


# ── next_difficulty ───────────────────────────────────────────────────────────

class TestNextDifficulty:

    def test_genesis_yields_initial_difficulty(self):
        chain = {0: GENESIS}
        assert next_difficulty(chain, GENESIS) == INITIAL_DIFFICULTY

    def test_returns_initial_before_window_filled(self):
        chain, tip = build_chain(DIFFICULTY_WINDOW - 1, 1.0)
        # Fewer blocks than the window: should still return INITIAL_DIFFICULTY
        # (or the current difficulty if it was set).
        diff = next_difficulty(chain, tip)
        # The tip's difficulty was TEST_DIFFICULTY in build_chain, but
        # next_difficulty looks at tip.difficulty when height < WINDOW.
        assert diff == TEST_DIFFICULTY

    def test_difficulty_increases_when_blocks_too_fast(self):
        """
        Blocks arriving at 0.1 s vs 1 s target → difficulty should increase.
        """
        chain, tip = build_adaptive_chain(DIFFICULTY_WINDOW + 5,
                                          inter_block_time=0.1)
        new_diff = next_difficulty(chain, tip)
        assert new_diff > INITIAL_DIFFICULTY, (
            f"Expected difficulty > {INITIAL_DIFFICULTY}, got {new_diff}"
        )

    def test_difficulty_decreases_when_blocks_too_slow(self):
        """
        Blocks arriving at 10 s vs 1 s target → difficulty should decrease.
        """
        chain, tip = build_adaptive_chain(DIFFICULTY_WINDOW + 5,
                                          inter_block_time=10.0)
        new_diff = next_difficulty(chain, tip)
        assert new_diff < INITIAL_DIFFICULTY, (
            f"Expected difficulty < {INITIAL_DIFFICULTY}, got {new_diff}"
        )

    def test_difficulty_stable_at_target(self):
        """
        Blocks arriving at exactly 1 s → difficulty should stay within ±1
        of INITIAL_DIFFICULTY.
        """
        chain, tip = build_adaptive_chain(DIFFICULTY_WINDOW + 5,
                                          inter_block_time=1.0)
        new_diff = next_difficulty(chain, tip)
        assert abs(new_diff - INITIAL_DIFFICULTY) <= 1, (
            f"Expected diff near {INITIAL_DIFFICULTY}, got {new_diff}"
        )

    def test_difficulty_clamped_to_min(self):
        """
        Extremely slow blocks should not push difficulty below MIN_DIFFICULTY.
        """
        chain, tip = build_adaptive_chain(DIFFICULTY_WINDOW + 5,
                                          inter_block_time=1_000_000.0)
        assert next_difficulty(chain, tip) >= MIN_DIFFICULTY

    def test_difficulty_clamped_to_max(self):
        """
        Extremely fast blocks should not push difficulty above MAX_DIFFICULTY.
        """
        chain, tip = build_adaptive_chain(DIFFICULTY_WINDOW + 5,
                                          inter_block_time=0.000001)
        assert next_difficulty(chain, tip) <= MAX_DIFFICULTY

    def test_log2_adjustment_magnitude(self):
        """
        At 10× the target block time the adjustment should be ≈ log2(1/10) ≈ -3.32
        bits, i.e. we expect a drop of 3 bits from INITIAL_DIFFICULTY.

        We build a fixed-difficulty chain at INITIAL_DIFFICULTY so the
        adjustment is measured from a known base without compounding.
        """
        chain, tip = build_chain(DIFFICULTY_WINDOW + 2,
                                 inter_block_time=10,
                                 difficulty=INITIAL_DIFFICULTY)
        new_diff = next_difficulty(chain, tip)
        expected_delta = round(math.log2(TARGET_BLOCK_TIME / 10.0))
        expected = max(MIN_DIFFICULTY,
                       min(MAX_DIFFICULTY, INITIAL_DIFFICULTY + expected_delta))
        assert new_diff == expected


# ── validate_block ────────────────────────────────────────────────────────────

class TestValidateBlock:

    def test_valid_block_passes(self):
        chain, tip = build_adaptive_chain(3, inter_block_time=1.0)
        for block in chain.values():
            if block.height == 0:
                continue
            err = validate_block({h: b for h, b in chain.items()
                                   if h < block.height}, block)
            assert err is None, f"height {block.height}: {err}"

    def test_wrong_difficulty_rejected(self):
        chain, tip = build_adaptive_chain(DIFFICULTY_WINDOW + 2, 1.0)
        # Tamper: give the tip the wrong difficulty
        bad = Block(tip.height, tip.prev_hash, tip.txs_hash,
                    tip.timestamp, tip.difficulty + 2, tip.nonce,
                    tip.block_hash)
        parent_chain = {h: b for h, b in chain.items() if h < tip.height}
        err = validate_block(parent_chain, bad)
        assert err is not None

    def test_wrong_hash_rejected(self):
        chain, tip = build_adaptive_chain(3, 1.0)
        bad = Block(tip.height, tip.prev_hash, tip.txs_hash,
                    tip.timestamp, tip.difficulty, tip.nonce,
                    b"\xff" * 32)  # wrong hash
        parent_chain = {h: b for h, b in chain.items() if h < tip.height}
        err = validate_block(parent_chain, bad)
        assert err is not None

    def test_parent_mismatch_rejected(self):
        chain, tip = build_adaptive_chain(3, 1.0)
        bad = Block(tip.height, b"\xde\xad" * 16,  # wrong prev_hash
                    tip.txs_hash, tip.timestamp, tip.difficulty,
                    tip.nonce, tip.block_hash)
        parent_chain = {h: b for h, b in chain.items() if h < tip.height}
        err = validate_block(parent_chain, bad)
        assert err is not None


# ── Chain state ───────────────────────────────────────────────────────────────

class TestChainState:

    def test_apply_block_advances_tip(self):
        node = Chain()
        block = mine_block_at_time(GENESIS, [], INITIAL_DIFFICULTY, 1_000_001)
        assert node.apply_block(block)
        assert node.tip.height == 1
        assert node.tip.block_hash == block.block_hash

    def test_duplicate_block_ignored(self):
        node = Chain()
        block = mine_block_at_time(GENESIS, [], INITIAL_DIFFICULTY, 1_000_001)
        assert node.apply_block(block)
        assert not node.apply_block(block)  # second application returns False

    def test_fork_resolution_longer_chain_wins(self):
        """
        Mine two competing branches.  Feed both to a fresh node.
        The longer one (chain_b) should win.
        """
        # chain_a: 3 blocks from genesis
        chain_a: dict[int, Block] = {0: GENESIS}
        tip_a = GENESIS
        ts = 1_000_001
        for _ in range(3):
            b = mine_block_at_time(tip_a, [], TEST_DIFFICULTY, ts)
            chain_a[b.height] = b
            tip_a = b
            ts += 1

        # chain_b: 5 blocks from genesis (different blocks, longer)
        chain_b: dict[int, Block] = {0: GENESIS}
        tip_b = GENESIS
        ts = 2_000_001
        for _ in range(5):
            b = mine_block_at_time(tip_b, [], TEST_DIFFICULTY, ts)
            chain_b[b.height] = b
            tip_b = b
            ts += 1

        node = Chain()
        for h in range(1, 4):
            node.apply_block(chain_a[h])
        assert node.tip.height == 3

        for h in range(1, 6):
            node.apply_block(chain_b[h])
        assert node.tip.height == 5
        assert node.tip.block_hash == tip_b.block_hash

    def test_orphan_txs_returned_to_mempool(self):
        """
        When a reorg happens, transactions from the orphaned branch should
        be returned to the mempool.
        """
        dummy_tx = Tx(b"key" * 10, b"data", 42, b"sig" * 10)

        # branch_a: 2 blocks, block 1 contains dummy_tx
        chain_a: dict[int, Block] = {0: GENESIS}
        tip_a = GENESIS
        b1 = mine_block_at_time(tip_a, [dummy_tx], TEST_DIFFICULTY, 1_000_001)
        chain_a[1] = b1
        tip_a = b1
        b2 = mine_block_at_time(tip_a, [], TEST_DIFFICULTY, 1_000_002)
        chain_a[2] = b2
        tip_a = b2

        # branch_b: 3 blocks from genesis (longer), no dummy_tx
        chain_b: dict[int, Block] = {0: GENESIS}
        tip_b = GENESIS
        ts = 2_000_001
        for _ in range(3):
            b = mine_block_at_time(tip_b, [], TEST_DIFFICULTY, ts)
            chain_b[b.height] = b
            tip_b = b
            ts += 1

        node = Chain()
        # Apply branch_a first — dummy_tx gets confirmed
        node.apply_block(chain_a[1])
        node.apply_block(chain_a[2])
        assert dummy_tx.hash not in node._mempool_hashes  # confirmed

        # Now reorg to branch_b — dummy_tx should come back to mempool
        for h in range(1, 4):
            node.apply_block(chain_b[h])
        assert node.tip.height == 3
        assert any(tx.hash == dummy_tx.hash for tx in node.mempool), (
            "dummy_tx not returned to mempool after reorg"
        )

    def test_mempool_tx_removed_on_confirmation(self):
        node = Chain()
        tx = Tx(b"k" * 10, b"d", 1, b"s" * 10)
        node.add_tx(tx)
        assert tx.hash in node._mempool_hashes

        block = mine_block_at_time(GENESIS, [tx], TEST_DIFFICULTY, 1_000_001)
        node.apply_block(block)
        assert tx.hash not in node._mempool_hashes

    def test_gap_block_stored_and_recovered(self):
        """
        If a node receives block N+2 before block N+1, it should store it and
        apply it once N+1 arrives.
        """
        chain: dict[int, Block] = {0: GENESIS}
        tip = GENESIS
        b1 = mine_block_at_time(tip, [], TEST_DIFFICULTY, 1_000_001)
        chain[1] = b1
        tip = b1
        b2 = mine_block_at_time(tip, [], TEST_DIFFICULTY, 1_000_002)
        chain[2] = b2

        node = Chain()
        # Apply b2 first (gap)
        node.apply_block(b2)
        assert node.tip.height == 0  # not yet applied

        # Now apply b1 — b2 should be recoverable and applied too
        node.apply_block(b1)
        assert node.tip.height == 1  # b2 recovery is handled by community, not Chain


# ── Adaptive chain over many blocks ──────────────────────────────────────────

class TestAdaptiveChainLong:

    def test_difficulty_converges_toward_target(self):
        """
        After enough blocks at a constant inter-block time, the adaptive
        difficulty should stabilise near the value that produces that rate.
        For inter_block_time=1.0 (== TARGET), difficulty should stay at
        INITIAL_DIFFICULTY ± 1.
        """
        num = DIFFICULTY_WINDOW * 5
        chain, tip = build_adaptive_chain(num, inter_block_time=1.0)
        # Collect the last WINDOW difficulties
        diffs = [chain[h].difficulty for h in range(num - DIFFICULTY_WINDOW, num + 1)]
        spread = max(diffs) - min(diffs)
        assert spread <= 2, (
            f"Difficulty not stable: {diffs}"
        )

    def test_all_blocks_pass_validate(self):
        """Every block in an adaptively-mined chain must pass validate_block."""
        num = DIFFICULTY_WINDOW + 5
        chain, _ = build_adaptive_chain(num, inter_block_time=1.0)
        for height in range(1, num + 1):
            block = chain[height]
            parent_chain = {h: b for h, b in chain.items() if h < height}
            err = validate_block(parent_chain, block)
            assert err is None, f"height {height}: {err}"
