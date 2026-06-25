# Blockchain Optional Challenges

Implementation of three optional assignment challenges on top of the py-ipv8 peer-to-peer framework.
Each challenge lives in its own directory with a standalone blockchain library, an IPv8 community, and a test suite.

```
challenge0/   Binary transfer of big blocks   (sliding-window transport)
challenge4/   Fork convergence                (reorg + orphan-tx recovery)
challenge5/   Adaptive difficulty             (log2 window adjustment)
```

---

## Prerequisites

```
pip install pytest
```

IPv8 and its dependencies are already present in the `py-ipv8` directory.
No other packages are required — the blockchain logic uses only the Python standard library (`hashlib`, `struct`, `asyncio`).

---

## Running the Test Suites

The `-p no:anyio` flag suppresses a Python 3.12 display bug in the `trio`/`anyio` packages that are pulled in as IPv8 dependencies.

```bash
cd c:\Blockchain

# Individual suites
python -m pytest challenge5/tests/ -v -p no:anyio
python -m pytest challenge4/tests/ -v -p no:anyio
python -m pytest challenge0/tests/ -v -p no:anyio

# All at once
python -m pytest challenge0/ challenge4/ challenge5/ -v -p no:anyio
```

Expected output: **72 tests pass** (~90 seconds total, most time spent mining real PoW blocks at low difficulty for the fork and difficulty tests).

---

## Test Design Philosophy

All three test suites use **real blockchain components** — actual SHA-256 mining, real block headers, real PoW validation. Nothing is mocked.

### Why Not Mock?

Mocking SHA-256 or the PoW check would hide bugs in the hash/header packing logic — exactly the bugs that matter in a real implementation. Past experience showed that mock-passing tests can fail on the actual server because the serialization format was wrong.

### Fast Tests Without Fake Data

Mining at production difficulty (`DIFFICULTY = 16`, which requires ~65 000 hashes on average) would make a 20-block test chain take several seconds. Instead, every test suite defines a low `TEST_DIFFICULTY`:

| Suite | `TEST_DIFFICULTY` | Expected hashes/block | Reason |
|-------|-------------------|-----------------------|--------|
| challenge4 | 4 | ~16 | Fast chains, many fork scenarios |
| challenge5 | 4 (default) | ~16 | Fast enough for difficulty window tests |
| challenge5 (magnitude test) | 16 | ~65 000 | Needs known base difficulty — still <1s for 12 blocks |

The blocks are structurally identical to production blocks: same 84-byte header, same SHA-256 hash, same leading-zero PoW check. Only the threshold is lower.

### Controlled Timestamps

Real wall-clock timestamps would make difficulty tests non-deterministic (the result depends on how fast the CPU mines). Instead, tests use `mine_block_at_time(tip, txs, difficulty, timestamp)` which mines with a **fixed timestamp** injected into the header. This lets tests set exact inter-block intervals:

```python
# Chain where blocks appear every 10 seconds (10× slower than target)
ts = 1_000_000
for _ in range(12):
    block = mine_block_at_time(tip, [], INITIAL_DIFFICULTY, ts)
    ts += 10
```

The nonce is still found by real SHA-256 search — only the timestamp field in the header is pinned.

### Test Chain Helpers

Each suite defines helpers that build real mined chains:

**challenge4 / challenge5:**

```python
make_branch(base, length, start_ts)   # mine `length` real blocks on top of `base`
build_chain(n, inter_block_time)      # fixed-difficulty chain with controlled timestamps
build_adaptive_chain(n, inter_block_time)  # difficulty adjusts each block via next_difficulty()
```

**challenge0:**

```python
make_data(n_bytes, seed)              # deterministic pseudorandom bytes (for large payloads)
pump_no_loss(data)                    # sender → receiver in memory, zero packet loss
pump_with_loss(data, drop_seqs)       # same but drops listed seq numbers on first attempt
```

The `pump_*` helpers wire `_Sender` and `_Receiver` together directly — no sockets, no asyncio event loop needed — so the core sliding-window logic can be tested synchronously and deterministically.

### What Each Test Class Covers

**`challenge5/tests/test_adaptive.py`**

| Class | Tests |
|-------|-------|
| `TestNextDifficulty` | genesis returns initial; pre-window unchanged; increases when fast; decreases when slow; stable at target; min/max clamps; log₂ magnitude |
| `TestValidateBlock` | valid block passes; wrong difficulty rejected; wrong hash rejected; prev_hash mismatch rejected |
| `TestChainState` | tip advances; duplicate ignored; fork resolution (longer wins); orphan txs return to mempool; confirmed tx removed; out-of-order gap block |
| `TestAdaptiveChainLong` | difficulty converges toward target over 30 blocks; all blocks pass validate_block |

**`challenge4/tests/test_fork.py`**

| Class | Tests |
|-------|-------|
| `TestBasicApply` | genesis tip; single block; duplicate ignored; three blocks; validate_chain clean |
| `TestForkResolution` | longer branch wins; shorter doesn't replace; fork at shared height; canonical valid after fork; tips set tracks all heads |
| `TestPartitionAndConvergence` | two partitions merge; canonical valid after merge; three-way fork; missing_heights reported correctly |
| `TestOrphanTxRecovery` | orphaned tx returns to mempool; tx in both branches not duplicated; multiple orphaned txs all recovered |
| `TestReorgDepthLimit` | shallow reorg accepted; deep reorg (> MAX_REORG_DEPTH) rejected |
| `TestOutOfOrder` | future block stored and resolved; all reversed; common_ancestor found |

**`challenge0/tests/test_transport.py`**

| Class | Tests |
|-------|-------|
| `TestSenderChunking` | empty data; exact chunk size; two-chunk boundary; large chunk count; window fills then closes; window re-opens after ACK |
| `TestReceiver` | in-order advances base; out-of-order delivery; SACK bitmap marks gaps; exact reassembly; duplicate chunk not stored twice |
| `TestFastRetransmit` | dup ACKs trigger retransmit; ACK advance resets dup counter |
| `TestTimeoutRetransmit` | no timeout when fresh; timeout after simulated delay |
| `TestFullTransferNoLoss` | small data; exact chunk size; multi-chunk; 50 KB; 500 KB |
| `TestTransferWithLoss` | single chunk dropped; first chunk dropped; last chunk dropped; multiple chunks dropped; every other chunk dropped |
| `TestTransportManager` | small transfer synchronous; large transfer (50 KB) synchronous |
| `TestBlockSerialisation` | roundtrip with txs; roundtrip no txs; large block (50 txs) survives full pump |

---

## Running as a Live Network

Each challenge's `community.py` exposes a `make_ipv8(key_file, port)` helper. A minimal 3-node launcher looks like this (replace the import with the desired challenge):

```python
import asyncio
from challenge4.community import make_ipv8   # or challenge0 / challenge5

async def main():
    nodes = [make_ipv8(f"node{i}.pem", 8910 + i) for i in range(3)]
    for node in nodes:
        await node.start()
    print("Nodes running — Ctrl-C to stop")
    await asyncio.Event().wait()

asyncio.run(main())
```

---

## Directory Structure

```
challenge0/
    __init__.py
    transport.py          sliding-window reliable transport protocol
    community.py          IPv8 community (large-block handshake + transport)
    tests/
        __init__.py
        test_transport.py  30 tests — chunking, SACK, loss recovery, block roundtrip

challenge4/
    __init__.py
    blockchain.py         fork-aware chain (all blocks stored, atomic reorg)
    community.py          IPv8 community (fork gossip, partition recovery)
    tests/
        __init__.py
        test_fork.py       22 tests — fork resolution, orphan tx, reorg depth, out-of-order

challenge5/
    __init__.py
    blockchain.py         adaptive-difficulty chain (log2 window adjustment)
    community.py          IPv8 community (mines with next_difficulty, validates incoming)
    tests/
        __init__.py
        test_adaptive.py   20 tests — difficulty convergence, clamping, fork + mempool reorg
```

---

## Challenge 5 — Adaptive Difficulty

### Problem

A static mining difficulty means block times drift as miners join or leave the network.
Too many miners → blocks arrive too fast.
Too few miners → the chain grinds to a halt.

### Approach

`next_difficulty()` in `challenge5/blockchain.py` looks at the last `DIFFICULTY_WINDOW = 10` blocks and compares their actual average inter-block time to the 1-second target:

```
actual_avg = (tip.timestamp - window_start.timestamp) / DIFFICULTY_WINDOW
delta      = log2(TARGET_BLOCK_TIME / actual_avg)
new_diff   = tip.difficulty + round(delta)
```

**Why log₂?**
Each additional bit of difficulty doubles the expected number of SHA-256 hashes required.
Adjusting in bit-space is equivalent to multiplicatively rescaling the expected work:

- Blocks arrived 2× too fast → `delta = log2(1 / 0.5) = +1` → difficulty up 1 bit (doubles work)
- Blocks arrived 4× too slow → `delta = log2(1 / 4) = -2` → difficulty down 2 bits (quarters work)

**Edge cases handled:**
- Genesis has timestamp `0` (not a real wall-clock time). The window is only computed once `tip.height > DIFFICULTY_WINDOW` so genesis is never included.
- Clamped to `[MIN_DIFFICULTY=4, MAX_DIFFICULTY=48]` so a single rogue timestamp cannot swing difficulty to an extreme.

### Key Files

| File | Role |
|------|------|
| `blockchain.py` | `next_difficulty()`, `mine_block_at_time()`, `validate_block()`, `Chain` |
| `community.py` | mines with adaptive difficulty, validates received blocks against `next_difficulty()` |
| `tests/test_adaptive.py` | tests difficulty increase/decrease/stability/clamping, validate_block, fork resolution, orphan tx |

---

## Challenge 4 — Fork Convergence

### Problem

When a network partition heals, two groups of nodes each hold a valid but divergent chain.
Naive implementations that store only one block per height cannot perform a reorg because the fork blocks are discarded as soon as the canonical chain advances.

### Approach

The core insight: **store every valid block ever seen, not just the canonical chain.**

`challenge4/blockchain.py` uses three collections:

```python
blocks:    dict[(height, block_hash), Block]   # all branches
canonical: dict[int, Block]                    # current winner only
tips:      set[bytes]                          # all live branch tips (not yet extended)
```

**When a new block arrives:**

1. Look up its parent in `blocks` (by `(height-1, prev_hash)`). If the parent is unknown, park the block in `_pending` keyed by `prev_hash` and wait — it will be applied automatically when the parent arrives.
2. Update `tips`: remove the parent hash, add the new block's hash.
3. If the new block's height exceeds the current tip, call `_reorg_to()`.

**Atomic reorg (`_reorg_to`):**

1. Walk back both the old tip and the new tip through `blocks` until the paths converge at a **common ancestor**.
2. Collect every transaction confirmed in the orphaned old branch (above the ancestor) that is absent from the new branch → add them back to the mempool.
3. Rewrite `canonical` in a single dict assignment (never expose a half-reorged state).
4. Remove from the mempool any tx now confirmed in the new canonical chain.

**Additional safeguards:**
- `MAX_REORG_DEPTH = 100` — refuse any reorg deeper than 100 blocks to prevent long-range attacks from rolling back confirmed history.
- `missing_heights(peer_height)` — after a partition heals, a node can call this to get the list of heights it needs to request from a peer in bulk.

### Key Files

| File | Role |
|------|------|
| `blockchain.py` | `Chain` with full fork storage, atomic reorg, orphan tx recovery, `missing_heights()` |
| `community.py` | periodic height polling (`GetChainHeight` every 10s), `AnnounceTip` gossip, out-of-order block resolution |
| `tests/test_fork.py` | fork resolution, 3-way partition + merge, orphan tx recovery, deep reorg rejection, out-of-order delivery |

---

## Challenge 0 — Binary Transfer of Big Blocks

### Problem

IPv8's `ez_send` delivers each call as a single UDP datagram.
The practical payload limit is roughly 1400 bytes (standard MTU minus IPv6/UDP headers).
A block carrying 50 transactions is easily 4–5 KB and simply cannot be sent in one call.

### Approach

A custom **sliding-window reliable transport protocol** is layered on top of IPv8's unreliable delivery, implemented in `challenge0/transport.py`.

#### Wire Messages

| Message | Purpose |
|---------|---------|
| `TransferInit(id, total_bytes, chunk_size, num_chunks)` | Receiver allocates state before chunks arrive |
| `DataChunk(id, seq, data)` | One 900-byte piece of the payload |
| `SelectiveAck(id, base, bitmap)` | Cumulative ACK + 256-bit SACK bitmap |
| `TransferDone(id)` | Signals the transfer is complete |

#### Sliding Window

The sender keeps up to `WINDOW_SIZE = 32` unACKed chunks in flight simultaneously.
This decouples throughput from per-round-trip latency — the sender does not need to wait one round trip per chunk.

#### Selective ACK (SACK)

Each ACK carries a **256-bit bitmap** above the cumulative base.
Bit `k` being set means "I have the chunk at `base + k`."
The sender uses this to retransmit only the specific missing chunks rather than everything after the first gap (go-back-N would be catastrophically slow at 32-chunk windows).

#### Fast Retransmit

If the same cumulative base arrives **3 times in a row** without advancing, the sender immediately retransmits the oldest unACKed chunk.
This recovers from a single dropped packet in ~3 round trips instead of waiting for the 200ms timeout.

#### Timeout Retransmit

A background task (50ms tick) scans for chunks whose `sent_at` timestamp is more than 200ms old and retransmits them.
This handles the case where the ACK itself was dropped.

#### Transfer IDs

Each transfer gets a random 16-byte ID so multiple concurrent transfers (e.g., two peers simultaneously requesting different large blocks) do not interfere.

#### Integration with the Blockchain Community

```
Block ≤ 800 bytes  →  AnnounceBlock (one UDP packet, existing path)

Block > 800 bytes  →  LargeBlockRef(height, hash)        [miner broadcasts]
                   →  RequestLargeBlock(hash)              [peer responds]
                   →  TransferInit + DataChunks + SACKs   [transport runs]
                   →  block deserialized and applied       [on reassembly]
```

The block serialization format is:
```
block_hash (32) | height (4) | prev_hash (32) | txs_hash (32) |
timestamp (8) | difficulty (4) | nonce (8) | n_txs (4) | [tx data]*
```

### Key Files

| File | Role |
|------|------|
| `transport.py` | `_Sender`, `_Receiver`, `TransportManager` — all transport logic |
| `community.py` | `LargeBlockRef`/`RequestLargeBlock` handshake, IPv8 payload wrappers, block serialize/deserialize |
| `tests/test_transport.py` | chunking, window mechanics, SACK bitmap, fast retransmit, 50KB/500KB transfers, loss recovery (single/multiple/alternating chunks dropped), block roundtrip |

---

## Block Header Format (all challenges)

All three challenges share the same 84-byte block header format inherited from the lab:

```
prev_hash   (32 bytes)  SHA-256 of the previous block
txs_hash    (32 bytes)  SHA-256 of all transaction hashes concatenated
timestamp    (8 bytes)  uint64 big-endian, Unix seconds
difficulty   (4 bytes)  uint32 big-endian, leading zero bits required
nonce        (8 bytes)  uint64 big-endian, search space for PoW
```

The block hash is `SHA-256(header)`.
Proof-of-work is satisfied when the first `difficulty` bits of the hash are all zero.
