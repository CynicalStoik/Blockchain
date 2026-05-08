"""
IPv8 Lab 1 client — PoW submission
====================================

"""

from __future__ import annotations

import asyncio
import hashlib
import os
import struct
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed

from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8_service import IPv8

# ── Identity — fill these in ───────────────────────────────────────────────────
EMAIL = "a.murali-2@student.tudelft.nl"           
GITHUB_URL = "https://github.com/CynicalStoik/Blockchain"  
KEY_FILE = "my_key.pem"                          

# ── Lab 1 constants (do not change) ───────────────────────────────────────────
COMMUNITY_ID = bytes.fromhex("2c1cc6e35ff484f99ebdfb6108477783c0102881")
SERVER_PUBLIC_KEY_BIN = bytes.fromhex(
    "4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb1"
    "78bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136"
    "c501ce5c09364e0ebb"
)
DIFFICULTY_BITS = 28  # need 28 leading zero bits in SHA-256 output


# ══════════════════════════════════════════════════════════════════════════════
# Proof of Work
# ══════════════════════════════════════════════════════════════════════════════

def _pow_worker(start: int, step: int, prefix: bytes) -> int | None:
    """
    Search for a valid nonce in the range [start, start+step, start+2*step, ...]
    for up to 2 000 000 iterations.  Returns the nonce on success, None otherwise.

    This function must be at module level so it is picklable on Windows.
    """
    nonce = start
    for _ in range(2_000_000):
        digest = hashlib.sha256(prefix + struct.pack(">q", nonce)).digest()
        # 28 leading zero bits: first 3 bytes == 0x00 AND high nibble of 4th byte == 0
        if digest[0] == 0 and digest[1] == 0 and digest[2] == 0 and digest[3] < 16:
            return nonce
        nonce += step
    return None


def compute_pow(email: str, github_url: str) -> int:
    """
    Find a nonce such that SHA256(email\\ngithub_url\\nnonce_8be) has 28 leading
    zero bits.  Uses all available CPU cores via ProcessPoolExecutor.
    """
    prefix = email.encode("utf-8") + b"\n" + github_url.encode("utf-8") + b"\n"
    num_workers = max(1, os.cpu_count() or 1)
    print(f"[PoW] Mining (difficulty={DIFFICULTY_BITS} bits, {num_workers} workers) …")
    print(f"[PoW] Expected ~{2**DIFFICULTY_BITS / 1e6:.0f}M hashes on average")

    t0 = time.time()
    offset = 0
    pool = ProcessPoolExecutor(max_workers=num_workers)
    try:
        while True:
            # Each worker searches 2 000 000 nonces interleaved by worker index.
            # Together one round covers offset … offset + num_workers*2_000_000 - 1.
            futures = [
                pool.submit(_pow_worker, offset + i, num_workers, prefix)
                for i in range(num_workers)
            ]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    elapsed = time.time() - t0
                    digest = hashlib.sha256(prefix + struct.pack(">q", result)).digest()
                    print(f"[PoW] Found nonce={result}  elapsed={elapsed:.1f}s")
                    print(f"[PoW] Hash: {digest.hex()}")
                    return result
            # Advance past the block we just searched
            offset += num_workers * 2_000_000
            elapsed = time.time() - t0
            rate = offset / elapsed / 1e6 if elapsed > 0 else 0
            print(f"[PoW] {offset / 1e6:.0f}M hashes in {elapsed:.1f}s  ({rate:.1f} MH/s) …")
    finally:
        # cancel_futures=True needs Python ≥3.9; requires Python ≥3.10 per spec anyway
        pool.shutdown(wait=False, cancel_futures=True)


# ══════════════════════════════════════════════════════════════════════════════
# Payloads
# ══════════════════════════════════════════════════════════════════════════════

@vp_compile
class SubmissionPayload(VariablePayload):
    """Message 1 — sent by client to server."""
    msg_id = 1
    format_list = ["varlenHutf8", "varlenHutf8", "q"]
    names = ["email", "github_url", "nonce"]


@vp_compile
class ResponsePayload(VariablePayload):
    """Message 2 — sent by server to client."""
    msg_id = 2
    format_list = ["?", "varlenHutf8"]
    names = ["success", "message"]


# ══════════════════════════════════════════════════════════════════════════════
# Community
# ══════════════════════════════════════════════════════════════════════════════

class Lab1Community(Community):
    """
    IPv8 community for the Lab 1 PoW submission.

    Constructor reads email / github_url / nonce from settings attributes set
    via the overlay 'initialize' config dict.
    """
    community_id = COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        # Values injected through the ConfigBuilder 'initialize' dict
        self.email: str = getattr(settings, "email", "")
        self.github_url: str = getattr(settings, "github_url", "")
        self.nonce: int = getattr(settings, "nonce", 0)

        # Signalled when the server responds (success or failure)
        self.done: asyncio.Event = asyncio.Event()

        self.add_message_handler(ResponsePayload, self.on_response)

    # ── Called by IPv8 once the overlay is running ─────────────────────────

    def started(self) -> None:
        """Register a periodic task to locate the server and send the submission."""
        self.register_task("find_server", self._find_and_submit, interval=2.0, delay=2.0)

    # ── Peer discovery & submission ────────────────────────────────────────

    async def _find_and_submit(self) -> None:
        """Scan visible peers for the server; send submission on first match."""
        peers = self.get_peers()
        for peer in peers:
            if peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY_BIN:
                print(f"[Net] Server found at {peer.address} — sending submission …")
                self.cancel_pending_task("find_server")
                self.ez_send(peer, SubmissionPayload(self.email, self.github_url, self.nonce))
                print("[Net] Submission sent — waiting for server response …")
                return
        print(f"[Net] Searching for server … {len(peers)} peer(s) visible so far")

    # ── Response handler ───────────────────────────────────────────────────

    @lazy_wrapper(ResponsePayload)
    def on_response(self, peer: Peer, payload: ResponsePayload) -> None:
        """Handle the server's response message."""
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY_BIN:
            print(f"[Net] Ignoring response from non-server peer {peer.address}")
            return
        status = "ACCEPTED" if payload.success else "REJECTED"
        print(f"\n{'=' * 60}")
        print(f"  Server response : {status}")
        print(f"  Message         : {payload.message}")
        print(f"{'=' * 60}\n")
        self.done.set()


# ══════════════════════════════════════════════════════════════════════════════
# Key management helpers
# ══════════════════════════════════════════════════════════════════════════════

def _check_credentials() -> None:
    """Warn the user if they forgot to fill in EMAIL / GITHUB_URL."""
    if EMAIL.endswith("@student.tudelft.nl") and "your.name" in EMAIL:
        print("[Error] Please set your EMAIL in main.py before running.")
        sys.exit(1)
    if "you/your-repo" in GITHUB_URL:
        print("[Error] Please set your GITHUB_URL in main.py before running.")
        sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
# IPv8 runner
# ══════════════════════════════════════════════════════════════════════════════

async def run_client(email: str, github_url: str, nonce: int) -> None:
    """Start IPv8, wait for the server response, then shut down cleanly."""
    builder = (
        ConfigBuilder()
        .clear_keys()
        .clear_overlays()
        .add_key("lab1", "curve25519", KEY_FILE)
        .add_overlay(
            "Lab1Community",
            "lab1",
            [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 3.0})],
            default_bootstrap_defs,
            {"email": email, "github_url": github_url, "nonce": nonce},
            [("started",)],
        )
    )

    ipv8 = IPv8(builder.finalize(), extra_communities={"Lab1Community": Lab1Community})
    await ipv8.start()

    community: Lab1Community = ipv8.overlays[0]
    pub_hex = community.my_peer.public_key.key_to_bin().hex()
    print(f"[Key] Public key : {pub_hex}")
    print(f"[Key] Key file   : {KEY_FILE}  ← back this up!")

    try:
        # Wait up to 5 minutes for the server to respond
        await asyncio.wait_for(community.done.wait(), timeout=300.0)
    except asyncio.TimeoutError:
        print("[Net] Timed out (300s) waiting for server response.")
        print("[Net] Possible causes: no route to server, packet signing issue,")
        print("[Net]   or server peer not yet discovered.  Try running again.")
    finally:
        await ipv8.stop()


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    _check_credentials()

    print(f"[Info] Email      : {EMAIL}")
    print(f"[Info] GitHub URL : {GITHUB_URL}")
    print()

    # PoW is computed synchronously BEFORE asyncio.run() so the multiprocessing
    # pool is created and torn down cleanly (required on Windows).
    nonce = compute_pow(EMAIL, GITHUB_URL)

    asyncio.run(run_client(EMAIL, GITHUB_URL, nonce))
