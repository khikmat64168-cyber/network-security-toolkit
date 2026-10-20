"""
SniffLoop — a blocking Scapy sniff that can be stopped from any thread.

Design decisions
────────────────
* scapy.sendrecv.sniff() with a stop_filter only re-checks the filter
  when a packet arrives, so stop() on a quiet interface could hang
  forever.  AsyncSniffer.stop() instead wakes the select loop through a
  close pipe and returns immediately.
* run() keeps the original blocking contract used by every monitor:
  it returns when the capture ends and re-raises exceptions from the
  sniffer thread (AsyncSniffer.join() does this), so callers keep
  translating PermissionError / OSError exactly as before.
* AsyncSniffer marks itself running slightly before its stop callback
  exists, so stop() retries until the sniffer thread has exited.  A
  lock makes "stop requested" and "sniffer created" atomic, so a stop()
  that races with run() can never be lost.
* KeyboardInterrupt delivered to the thread blocked in run() stops the
  sniffer thread before propagating, so Ctrl-C never leaves a capture
  running in the background.
* sniff()'s `timeout` keyword is handled here (wait, then stop): scapy
  2.8 rejects it on AsyncSniffer, older versions accept it.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Optional

_STOP_TIMEOUT_SECS = 3.0


class SniffLoop:
    """
    One stoppable capture run.

    Usage
    ─────
        loop = SniffLoop()
        loop.run(iface="en0", prn=callback, store=False)   # blocks
        # from another thread:
        loop.stop()
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop_requested = threading.Event()
        self._sniffer: Optional[Any] = None

    @property
    def stop_requested(self) -> bool:
        return self._stop_requested.is_set()

    def run(self, **sniff_kwargs: Any) -> None:
        """
        Sniff with *sniff_kwargs* (the same keywords as scapy's sniff())
        until the capture ends or stop() is called.  Blocks the caller.
        """
        from scapy.sendrecv import AsyncSniffer

        user_stop_filter = sniff_kwargs.pop("stop_filter", None)
        timeout: Optional[float] = sniff_kwargs.pop("timeout", None)

        def _stop_filter(pkt: Any) -> bool:
            if self._stop_requested.is_set():
                return True
            return bool(user_stop_filter(pkt)) if user_stop_filter else False

        with self._lock:
            if self._stop_requested.is_set():
                return
            sniffer = AsyncSniffer(stop_filter=_stop_filter, **sniff_kwargs)
            self._sniffer = sniffer
            sniffer.start()

        try:
            if timeout:
                thread = sniffer.thread
                if thread is not None:
                    thread.join(timeout)
                self._halt(sniffer)
            sniffer.join()   # re-raises an exception from the sniffer thread
        finally:
            self._halt(sniffer)

    def stop(self) -> None:
        """Stop the capture as soon as possible.  Safe from any thread."""
        with self._lock:
            self._stop_requested.set()
            sniffer = self._sniffer
        if sniffer is not None:
            self._halt(sniffer)

    # ── Internal ────────────────────────────────────────────────────────────

    @staticmethod
    def _halt(sniffer: Any) -> None:
        """Ask *sniffer* to stop until its thread has really exited."""
        thread = getattr(sniffer, "thread", None)
        if thread is None or thread is threading.current_thread():
            return
        deadline = time.monotonic() + _STOP_TIMEOUT_SECS
        while thread.is_alive() and time.monotonic() < deadline:
            if getattr(sniffer, "running", False):
                try:
                    sniffer.stop(join=False)
                except Exception:   # noqa: BLE001 — not ready yet; retry
                    pass
            thread.join(0.05)
