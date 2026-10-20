"""
Unit tests for SniffLoop (nst/sniffer/loop.py).

AsyncSniffer is replaced by a fake whose thread blocks until stopped,
mimicking a quiet interface where no packet ever arrives.
"""
from __future__ import annotations

import threading
import time
from typing import Any, List

import pytest

from nst.sniffer.loop import SniffLoop


class _FakeAsyncSniffer:
    instances: List["_FakeAsyncSniffer"] = []

    def __init__(self, **kwargs: Any) -> None:
        if "timeout" in kwargs:   # scapy 2.8 behaviour
            raise ValueError("'timeout' isn't supported with AsyncSniffer")
        self.kwargs = kwargs
        self.running = False
        self.exception: BaseException | None = kwargs.pop("_raise", None)
        self._released = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        _FakeAsyncSniffer.instances.append(self)

    def _run(self) -> None:
        self.running = True
        if self.exception is None:
            self._released.wait(10)
        self.running = False

    def start(self) -> None:
        self.thread.start()

    def join(self) -> None:
        self.thread.join()
        if self.exception is not None:
            raise self.exception

    def stop(self, join: bool = True) -> None:
        self._released.set()


@pytest.fixture()
def fake_sniffer(monkeypatch: pytest.MonkeyPatch) -> type[_FakeAsyncSniffer]:
    import scapy.sendrecv

    _FakeAsyncSniffer.instances = []
    monkeypatch.setattr(scapy.sendrecv, "AsyncSniffer", _FakeAsyncSniffer)
    return _FakeAsyncSniffer


def _start(loop: SniffLoop, **kwargs: Any) -> threading.Thread:
    thread = threading.Thread(target=lambda: loop.run(**kwargs), daemon=True)
    thread.start()
    return thread


class TestSniffLoop:
    def test_stop_ends_quiet_capture_immediately(self, fake_sniffer: Any) -> None:
        loop = SniffLoop()
        thread = _start(loop, iface="lo0")
        time.sleep(0.05)
        started = time.monotonic()
        loop.stop()
        thread.join(2)
        assert not thread.is_alive()
        assert time.monotonic() - started < 1.0

    def test_stop_before_run_skips_capture(self, fake_sniffer: Any) -> None:
        loop = SniffLoop()
        loop.stop()
        loop.run(iface="lo0")
        assert fake_sniffer.instances == []
        assert loop.stop_requested

    def test_immediate_stop_never_hangs(self, fake_sniffer: Any) -> None:
        for _ in range(25):
            loop = SniffLoop()
            thread = _start(loop, iface="lo0")
            loop.stop()
            thread.join(2)
            assert not thread.is_alive()

    def test_sniffer_exception_is_reraised(self, fake_sniffer: Any) -> None:
        with pytest.raises(PermissionError):
            SniffLoop().run(_raise=PermissionError("bpf denied"))

    def test_kwargs_forwarded_and_stop_filter_wrapped(self, fake_sniffer: Any) -> None:
        loop = SniffLoop()
        thread = _start(loop, iface="en0", store=False, stop_filter=lambda _p: False)
        time.sleep(0.05)
        sniffer = fake_sniffer.instances[0]
        assert sniffer.kwargs["iface"] == "en0"
        assert sniffer.kwargs["store"] is False
        assert sniffer.kwargs["stop_filter"](None) is False
        loop.stop()
        assert sniffer.kwargs["stop_filter"](None) is True
        thread.join(2)

    def test_timeout_is_handled_by_the_loop(self, fake_sniffer: Any) -> None:
        loop = SniffLoop()
        started = time.monotonic()
        loop.run(iface="lo0", timeout=0.2)
        elapsed = time.monotonic() - started
        assert 0.15 <= elapsed < 2.0
        assert "timeout" not in fake_sniffer.instances[0].kwargs
