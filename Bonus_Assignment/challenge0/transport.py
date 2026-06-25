"""
Challenge 0 — Big Block Transfer: Sliding-Window Reliable Transport

Removes the 1-UDP-message limitation of IPv8 by layering a simple
reliable, ordered byte-stream on top of unreliable datagrams.

Design goals (from the spec)
─────────────────────────────
  • Sliding window      — up to WINDOW_SIZE chunks in flight simultaneously.
  • Fast retransmit     — retransmit the oldest unACKed chunk when the same
                          cumulative ACK base is received FAST_RETRANSMIT_DUP
                          times without advancing.
  • Selective ACK       — a 256-bit bitmap above the cumulative base lets the
                          receiver tell the sender exactly which chunks it has,
                          so the sender only retransmits the gaps.
  • No silly-window     — sender never sends a chunk smaller than CHUNK_SIZE
                          unless it is the final chunk.
  • No head-of-line     — each transfer gets its own ID; multiple concurrent
                          transfers to the same peer do not block each other.
  • Congestion control  — omitted intentionally (single-hop LAN / loopback
                          between three nodes; QUIC-style CC is overkill).

Wire format
───────────
  TransferInit  — announces a new transfer (id, total bytes, chunk size).
  DataChunk     — one chunk of payload data (id, seq, data).
  SelectiveAck  — cumulative base + 256-bit SACK bitmap (id, base, bitmap).
  TransferDone  — sender signals all chunks have been ACKed (id).

Usage (from community code)
───────────────────────────
  manager = TransportManager(send_fn, on_complete_fn)
  # send
  tid = manager.start_send(peer, data)          # non-blocking; chunks queued
  await manager.drain()                         # optional: wait for completion
  # receive — handled automatically via:
  manager.on_init(peer, payload)
  manager.on_chunk(peer, payload)
  manager.on_ack(peer, payload)
"""
from __future__ import annotations

import asyncio
import os
import struct
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Awaitable

CHUNK_SIZE: int = 900               # bytes per data chunk (leaves room for headers)
WINDOW_SIZE: int = 32               # max unACKed chunks in flight
RETRANSMIT_TIMEOUT: float = 0.2     # seconds before retransmitting
FAST_RETRANSMIT_DUP: int = 3        # duplicate ACKs before fast retransmit
SACK_BITS: int = 256                # how many chunks above base the SACK bitmap covers


# ── Wire types (plain dataclasses — serialised by community.py payloads) ─────

@dataclass
class TransferInit:
    transfer_id: bytes    # 16-byte random ID
    total_bytes: int
    chunk_size: int
    num_chunks: int


@dataclass
class DataChunk:
    transfer_id: bytes
    seq: int
    data: bytes


@dataclass
class SelectiveAck:
    transfer_id: bytes
    base: int             # next expected seq (cumulative ACK)
    bitmap: bytes         # SACK_BITS bits, one per chunk above base


@dataclass
class TransferDone:
    transfer_id: bytes


# ── Receiver state ────────────────────────────────────────────────────────────

class _Receiver:
    """Tracks one inbound transfer."""

    def __init__(self, tid: bytes, total_bytes: int,
                 chunk_size: int, num_chunks: int) -> None:
        self.tid = tid
        self.total_bytes = total_bytes
        self.chunk_size = chunk_size
        self.num_chunks = num_chunks
        self._chunks: dict[int, bytes] = {}  # seq → data
        self._base: int = 0                  # next expected seq

    def receive(self, seq: int, data: bytes) -> None:
        if seq not in self._chunks:
            self._chunks[seq] = data
        # Eagerly advance base so `complete` is correct immediately
        while self._base in self._chunks:
            self._base += 1

    def make_ack(self) -> SelectiveAck:
        # Build SACK bitmap for chunks above base
        bitmap = bytearray(SACK_BITS // 8)
        for seq, _ in self._chunks.items():
            offset = seq - self._base
            if 0 < offset < SACK_BITS:
                bitmap[offset // 8] |= 1 << (offset % 8)
        return SelectiveAck(self.tid, self._base, bytes(bitmap))

    @property
    def complete(self) -> bool:
        return self._base >= self.num_chunks

    def reassemble(self) -> bytes:
        parts: list[bytes] = []
        for i in range(self.num_chunks):
            parts.append(self._chunks.get(i, b""))
        return b"".join(parts)[: self.total_bytes]


# ── Sender state ──────────────────────────────────────────────────────────────

@dataclass
class _Chunk:
    seq: int
    data: bytes
    sent_at: float = 0.0


class _Sender:
    """Tracks one outbound transfer with sliding-window + SACK logic."""

    def __init__(self, tid: bytes, data: bytes, peer: object) -> None:
        self.tid = tid
        self.peer = peer
        self.total_bytes = len(data)
        self.chunk_size = CHUNK_SIZE
        self._chunks: list[_Chunk] = []
        self._base: int = 0          # oldest unACKed seq
        self._next_seq: int = 0      # next seq to send
        self._dup_count: int = 0     # consecutive duplicate ACKs
        self._last_base: int = -1
        self.done: asyncio.Event = asyncio.Event()

        # Slice data into chunks
        offset = 0
        while offset < len(data) or not self._chunks:
            chunk_data = data[offset: offset + CHUNK_SIZE]
            self._chunks.append(_Chunk(len(self._chunks), chunk_data))
            offset += CHUNK_SIZE

        self.num_chunks = len(self._chunks)

    @property
    def window_open(self) -> bool:
        return self._next_seq < self._base + WINDOW_SIZE and self._next_seq < self.num_chunks

    def next_to_send(self) -> _Chunk | None:
        if self.window_open:
            chunk = self._chunks[self._next_seq]
            chunk.sent_at = time.monotonic()
            self._next_seq += 1
            return chunk
        return None

    def on_ack(self, ack: SelectiveAck) -> list[int]:
        """
        Process a SACK.  Returns a list of seq numbers to retransmit.
        """
        to_retransmit: list[int] = []

        if ack.base > self._base:
            self._base = ack.base
            self._next_seq = max(self._next_seq, self._base)
            self._dup_count = 0
        else:
            # Any non-advancing ACK counts as a duplicate
            self._dup_count += 1
        self._last_base = ack.base

        if self._base >= self.num_chunks:
            self.done.set()
            return []

        # Fast retransmit on duplicate ACKs
        if self._dup_count >= FAST_RETRANSMIT_DUP:
            to_retransmit.append(self._base)
            self._dup_count = 0

        # Gap retransmit using SACK bitmap: any seq in [base, base+SACK_BITS)
        # that is NOT marked in the bitmap is a hole → retransmit
        now = time.monotonic()
        for offset in range(1, min(SACK_BITS, self.num_chunks - self._base)):
            seq = self._base + offset
            if seq >= self.num_chunks:
                break
            byte_idx = offset // 8
            bit_idx = offset % 8
            received = bool(ack.bitmap[byte_idx] & (1 << bit_idx))
            chunk = self._chunks[seq]
            if not received and now - chunk.sent_at > RETRANSMIT_TIMEOUT:
                to_retransmit.append(seq)
                chunk.sent_at = now

        return to_retransmit

    def timed_out_seqs(self) -> list[int]:
        """Return seq numbers of chunks that have been in-flight too long."""
        now = time.monotonic()
        result: list[int] = []
        for seq in range(self._base, min(self._next_seq, self.num_chunks)):
            chunk = self._chunks[seq]
            if chunk.sent_at > 0 and now - chunk.sent_at > RETRANSMIT_TIMEOUT:
                result.append(seq)
                chunk.sent_at = now
        return result


# ── Transport manager ─────────────────────────────────────────────────────────

SendFn = Callable[[object, object], None]
CompleteFn = Callable[[object, bytes], Awaitable[None]]


class TransportManager:
    """
    Manages all concurrent inbound and outbound transfers.

    Parameters
    ----------
    send_fn:      callable(peer, wire_object) — used to send DataChunk /
                  SelectiveAck / TransferDone etc. via IPv8's ez_send.
    on_complete:  async callable(peer, data) — called when a full transfer
                  has been received and reassembled.
    tick_interval: seconds between proactive retransmit scans.
    """

    def __init__(self, send_fn: SendFn,
                 on_complete: CompleteFn,
                 tick_interval: float = 0.05) -> None:
        self._send = send_fn
        self._on_complete = on_complete
        self._tick_interval = tick_interval
        self._senders: dict[bytes, _Sender] = {}
        self._receivers: dict[bytes, _Receiver] = {}
        self._task: asyncio.Task | None = None

    # ── Sender API ────────────────────────────────────────────────────────────

    def start_send(self, peer: object, data: bytes) -> bytes:
        """
        Begin sending *data* to *peer*.  Returns the transfer ID.
        The first message sent immediately is TransferInit so the receiver
        can allocate state before any chunks arrive.
        """
        tid = os.urandom(16)
        sender = _Sender(tid, data, peer)
        self._senders[tid] = sender
        # Send init
        self._send(peer, TransferInit(tid, sender.total_bytes,
                                      CHUNK_SIZE, sender.num_chunks))
        # Fill the initial window
        while sender.window_open:
            chunk = sender.next_to_send()
            if chunk:
                self._send(peer, DataChunk(tid, chunk.seq, chunk.data))
        return tid

    async def wait_for_send(self, tid: bytes) -> None:
        """Await until the transfer identified by *tid* is fully ACKed."""
        sender = self._senders.get(tid)
        if sender:
            await sender.done.wait()
            self._senders.pop(tid, None)

    # ── Receiver callbacks (called by community message handlers) ─────────────

    def on_init(self, peer: object, msg: TransferInit) -> None:
        tid = msg.transfer_id
        if tid not in self._receivers:
            self._receivers[tid] = _Receiver(
                tid, msg.total_bytes, msg.chunk_size, msg.num_chunks,
            )

    def on_chunk(self, peer: object, msg: DataChunk) -> None:
        tid = msg.transfer_id
        recv = self._receivers.get(tid)
        if recv is None:
            return
        recv.receive(msg.seq, msg.data)
        ack = recv.make_ack()
        self._send(peer, ack)
        if recv.complete:
            data = recv.reassemble()
            self._receivers.pop(tid, None)
            self._send(peer, TransferDone(tid))
            # Schedule callback in the event loop
            asyncio.get_event_loop().create_task(self._on_complete(peer, data))

    def on_ack(self, peer: object, msg: SelectiveAck) -> None:
        sender = self._senders.get(msg.transfer_id)
        if sender is None:
            return
        retransmit_seqs = sender.on_ack(msg)
        # Fill window with new chunks
        while sender.window_open:
            chunk = sender.next_to_send()
            if chunk:
                self._send(peer, DataChunk(msg.transfer_id, chunk.seq, chunk.data))
        # Retransmit gaps indicated by SACK
        for seq in retransmit_seqs:
            chunk = sender._chunks[seq]
            self._send(peer, DataChunk(msg.transfer_id, seq, chunk.data))
        if sender.done.is_set():
            self._senders.pop(msg.transfer_id, None)
            self._send(peer, TransferDone(msg.transfer_id))

    def on_done(self, peer: object, msg: TransferDone) -> None:
        # Sender side: peer confirmed receipt
        sender = self._senders.pop(msg.transfer_id, None)
        if sender:
            sender.done.set()

    # ── Background tick (retransmit on timeout) ────────────────────────────────

    def start(self) -> None:
        """Start the background retransmit timer.  Call once from community.started()."""
        self._task = asyncio.get_event_loop().create_task(self._tick_loop())

    def stop(self) -> None:
        if self._task:
            self._task.cancel()

    async def _tick_loop(self) -> None:
        while True:
            await asyncio.sleep(self._tick_interval)
            for tid, sender in list(self._senders.items()):
                seqs = sender.timed_out_seqs()
                for seq in seqs:
                    chunk = sender._chunks[seq]
                    self._send(sender.peer, DataChunk(tid, seq, chunk.data))
                # Also push new chunks into window
                while sender.window_open:
                    chunk = sender.next_to_send()
                    if chunk:
                        self._send(sender.peer,
                                   DataChunk(tid, chunk.seq, chunk.data))
