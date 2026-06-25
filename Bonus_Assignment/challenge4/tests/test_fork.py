"""
Challenge 4 — Fork Convergence: test suite
All tests build *real* chains by mining actual SHA-256 PoW blocks at low
difficulty.  No mocking.
"""
from __future__ import annotations

import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from challenge4.blockchain import (
    GENESIS, DIFFICULTY, MAX_REORG_DEPTH,
    Block, Tx, Chain,
    mine_block_at_time, check_pow,
    compute_block_hash, compute_txs_hash,
)

TEST_DIFF = 4   # very low difficulty → fast tests


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_branch(base: Block, length: int,
                start_ts: int = 1_000_000,
                txs_per_block: list[list[Tx]] | None = None) -> list[Block]:
    """
    Mine *length* real blocks on top of *base*.
    Returns the list of new blocks (not including *base*).
    """
    blocks: list[Block] = []
    tip = base
    ts = start_ts
    for i in range(length):
        txs = (txs_per_block[i] if txs_per_block and i < len(txs_per_block)
               else [])
        b = mine_block_at_time(tip, txs, TEST_DIFF, ts)
        blocks.append(b)
        tip = b
        ts += 1
    return blocks


def apply_branch(node: Chain, branch: list[Block]) -> None:
    for b in branch:
        node.apply_block(b)


# ── Basic apply / tip tracking ────────────────────────────────────────────────

class TestBasicApply:

    def test_genesis_is_initial_tip(self):
        node = Chain()
        assert node.tip.block_hash == GENESIS.block_hash
        assert node.tip.height == 0

    def test_apply_single_block_advances_tip(self):
        node = Chain()
        branch = make_branch(GENESIS, 1)
        node.apply_block(branch[0])
        assert node.tip.height == 1

    def test_duplicate_block_ignored(self):
        node = Chain()
        branch = make_branch(GENESIS, 1)
        assert node.apply_block(branch[0]) is True
        assert node.apply_block(branch[0]) is False

    def test_chain_three_blocks(self):
        node = Chain()
        branch = make_branch(GENESIS, 3)
        apply_branch(node, branch)
        assert node.tip.height == 3
        assert node.tip.block_hash == branch[-1].block_hash

    def test_canonical_chain_is_valid(self):
        node = Chain()
        apply_branch(node, make_branch(GENESIS, 5))
        errors = node.validate_chain()
        assert errors == [], errors


# ── Fork detection and longest-chain resolution ───────────────────────────────

class TestForkResolution:

    def test_longer_branch_wins_simple(self):
        """
        Branch A (3 blocks) is applied first, then branch B (5 blocks).
        The node should switch to B.
        """
        node = Chain()
        branch_a = make_branch(GENESIS, 3, start_ts=1_000_000)
        branch_b = make_branch(GENESIS, 5, start_ts=2_000_000)

        apply_branch(node, branch_a)
        assert node.tip.height == 3

        apply_branch(node, branch_b)
        assert node.tip.height == 5
        assert node.tip.block_hash == branch_b[-1].block_hash

    def test_shorter_branch_does_not_replace_tip(self):
        node = Chain()
        branch_a = make_branch(GENESIS, 5, start_ts=1_000_000)
        branch_b = make_branch(GENESIS, 3, start_ts=2_000_000)

        apply_branch(node, branch_a)
        apply_branch(node, branch_b)
        assert node.tip.height == 5
        assert node.tip.block_hash == branch_a[-1].block_hash

    def test_fork_at_height_2(self):
        """Two chains share blocks 0-2, then diverge."""
        node = Chain()
        shared = make_branch(GENESIS, 2, start_ts=1_000_000)
        apply_branch(node, shared)
        fork_base = shared[-1]

        branch_a = make_branch(fork_base, 3, start_ts=3_000_000)
        branch_b = make_branch(fork_base, 5, start_ts=4_000_000)

        apply_branch(node, branch_a)
        apply_branch(node, branch_b)
        assert node.tip.height == 7   # 2 shared + 5 new
        assert node.tip.block_hash == branch_b[-1].block_hash

    def test_canonical_chain_consistent_after_fork(self):
        node = Chain()
        branch_a = make_branch(GENESIS, 3, start_ts=1_000_000)
        branch_b = make_branch(GENESIS, 5, start_ts=2_000_000)

        apply_branch(node, branch_a)
        apply_branch(node, branch_b)

        errors = node.validate_chain()
        assert errors == [], errors

    def test_tips_set_tracks_all_heads(self):
        node = Chain()
        branch_a = make_branch(GENESIS, 2, start_ts=1_000_000)
        branch_b = make_branch(GENESIS, 2, start_ts=2_000_000)

        apply_branch(node, branch_a)
        apply_branch(node, branch_b)

        # Both branch tips should be in the tips set
        assert branch_a[-1].block_hash in node.tips
        assert branch_b[-1].block_hash in node.tips


# ── Partition simulation ──────────────────────────────────────────────────────

class TestPartitionAndConvergence:

    def test_two_partitions_then_merge(self):
        """
        Simulate two partitioned groups mining independently, then reconnecting.

        Group A: node_a mines 4 blocks.
        Group B: node_b mines 6 blocks.
        After merge, both should be at height 6 with the same tip.
        """
        node_a = Chain()
        node_b = Chain()

        # --- PARTITION: each group mines independently ---
        branch_a = make_branch(GENESIS, 4, start_ts=1_000_000)
        branch_b = make_branch(GENESIS, 6, start_ts=2_000_000)

        apply_branch(node_a, branch_a)
        apply_branch(node_b, branch_b)

        assert node_a.tip.height == 4
        assert node_b.tip.height == 6

        # --- RECONNECT: exchange blocks ---
        # node_a receives all of node_b's blocks
        apply_branch(node_a, branch_b)
        # node_b receives all of node_a's blocks
        apply_branch(node_b, branch_a)

        # Both should converge to the longer chain (branch_b)
        assert node_a.tip.height == 6
        assert node_b.tip.height == 6
        assert node_a.tip.block_hash == node_b.tip.block_hash == branch_b[-1].block_hash

    def test_convergence_canonical_chain_valid(self):
        node_a = Chain()
        branch_a = make_branch(GENESIS, 3, start_ts=1_000_000)
        branch_b = make_branch(GENESIS, 5, start_ts=2_000_000)

        apply_branch(node_a, branch_a)
        apply_branch(node_a, branch_b)

        errors = node_a.validate_chain()
        assert errors == [], errors

    def test_three_way_partition(self):
        """Three groups mine independently; all should converge to the longest."""
        node = Chain()
        branch_a = make_branch(GENESIS, 3, start_ts=1_000_000)
        branch_b = make_branch(GENESIS, 5, start_ts=2_000_000)
        branch_c = make_branch(GENESIS, 7, start_ts=3_000_000)

        apply_branch(node, branch_a)
        apply_branch(node, branch_b)
        apply_branch(node, branch_c)

        assert node.tip.height == 7
        assert node.tip.block_hash == branch_c[-1].block_hash

    def test_missing_heights_reported_correctly(self):
        node = Chain()
        apply_branch(node, make_branch(GENESIS, 3))
        assert node.missing_heights(6) == [4, 5, 6]
        assert node.missing_heights(3) == []


# ── Orphan transaction recovery ───────────────────────────────────────────────

class TestOrphanTxRecovery:

    def _make_tx(self, label: bytes) -> Tx:
        return Tx(b"k" * 32, label, 42, b"s" * 64)

    def test_orphaned_tx_returns_to_mempool(self):
        """
        tx_a is confirmed in branch_a (height 1).
        branch_b is longer and does NOT contain tx_a.
        After the reorg, tx_a should be in the mempool.
        """
        tx_a = self._make_tx(b"tx_a")
        node = Chain()

        block_a1 = mine_block_at_time(GENESIS, [tx_a], TEST_DIFF, 1_000_001)
        block_a2 = mine_block_at_time(block_a1, [], TEST_DIFF, 1_000_002)

        branch_b = make_branch(GENESIS, 3, start_ts=2_000_000)

        node.apply_block(block_a1)
        node.apply_block(block_a2)
        # tx_a is confirmed — should NOT be in mempool
        assert tx_a.hash not in node._mempool_hashes

        apply_branch(node, branch_b)
        assert node.tip.height == 3

        # After reorg: tx_a was confirmed in the orphaned branch → back in mempool
        assert any(tx.hash == tx_a.hash for tx in node.mempool), (
            "tx_a should be in mempool after reorg"
        )

    def test_tx_confirmed_in_both_branches_not_duplicated(self):
        """
        tx_shared is mined in BOTH branch_a and branch_b.
        After the reorg, tx_shared should NOT appear in the mempool.
        """
        tx_shared = self._make_tx(b"shared")
        node = Chain()

        block_a = mine_block_at_time(GENESIS, [tx_shared], TEST_DIFF, 1_000_001)
        block_b1 = mine_block_at_time(GENESIS, [tx_shared], TEST_DIFF, 2_000_001)
        block_b2 = mine_block_at_time(block_b1, [], TEST_DIFF, 2_000_002)
        block_b3 = mine_block_at_time(block_b2, [], TEST_DIFF, 2_000_003)

        node.apply_block(block_a)
        node.apply_block(block_b1)
        node.apply_block(block_b2)
        node.apply_block(block_b3)

        assert tx_shared.hash not in node._mempool_hashes

    def test_multiple_orphaned_txs_all_recovered(self):
        txs = [self._make_tx(f"tx_{i}".encode()) for i in range(5)]
        node = Chain()

        tip = GENESIS
        ts = 1_000_001
        branch_a: list[Block] = []
        for tx in txs:
            b = mine_block_at_time(tip, [tx], TEST_DIFF, ts)
            branch_a.append(b)
            tip = b
            ts += 1

        # branch_b is longer with no txs
        branch_b = make_branch(GENESIS, len(txs) + 2, start_ts=2_000_000)

        apply_branch(node, branch_a)
        apply_branch(node, branch_b)

        mempool_hashes = {tx.hash for tx in node.mempool}
        for tx in txs:
            assert tx.hash in mempool_hashes, f"{tx.data} not in mempool after reorg"


# ── Reorg depth limit ─────────────────────────────────────────────────────────

class TestReorgDepthLimit:

    def test_shallow_reorg_accepted(self):
        node = Chain()
        branch_a = make_branch(GENESIS, MAX_REORG_DEPTH - 1, start_ts=1_000_000)
        branch_b = make_branch(GENESIS, MAX_REORG_DEPTH + 1, start_ts=2_000_000)

        apply_branch(node, branch_a)
        apply_branch(node, branch_b)
        # branch_b is longer and shallow enough → should win
        assert node.tip.block_hash == branch_b[-1].block_hash

    def test_deep_reorg_rejected(self):
        node = Chain()
        # Establish canonical chain of MAX_REORG_DEPTH + 10 blocks
        canonical = make_branch(GENESIS, MAX_REORG_DEPTH + 10, start_ts=1_000_000)
        apply_branch(node, canonical)
        tip_before = node.tip.block_hash

        # Attacker tries a reorg starting from genesis (depth > MAX_REORG_DEPTH)
        attack_chain = make_branch(GENESIS, MAX_REORG_DEPTH + 20, start_ts=9_000_000)
        apply_branch(node, attack_chain)

        # The tip should NOT have changed to the attack chain
        assert node.tip.block_hash == tip_before, (
            "Deep reorg should have been rejected"
        )


# ── Out-of-order / gap block delivery ────────────────────────────────────────

class TestOutOfOrder:

    def test_future_block_stored_and_resolved(self):
        """
        Receive block 3 before block 2.
        Once block 2 arrives, block 3 should be applied automatically.
        """
        node = Chain()
        branch = make_branch(GENESIS, 3)

        # Deliver out of order: 1, 3, 2
        node.apply_block(branch[0])   # height 1 — ok
        node.apply_block(branch[2])   # height 3 — pending (parent unknown)
        assert node.tip.height == 1

        node.apply_block(branch[1])   # height 2 — should resolve height 3 too
        assert node.tip.height == 3

    def test_all_out_of_order(self):
        node = Chain()
        branch = make_branch(GENESIS, 4)
        # Reverse order
        for b in reversed(branch):
            node.apply_block(b)
        assert node.tip.height == 4

    def test_common_ancestor_found(self):
        node = Chain()
        shared = make_branch(GENESIS, 2, start_ts=1_000_000)
        apply_branch(node, shared)

        fork_a = make_branch(shared[-1], 2, start_ts=3_000_000)
        apply_branch(node, fork_a)

        # common_ancestor of fork_a tip should be shared[-1]
        ancestor = node.common_ancestor(fork_a[-1])
        assert ancestor is not None
        assert ancestor.block_hash == fork_a[-1].block_hash  # tip itself is canonical
