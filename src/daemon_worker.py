"""Cancellable background worker that cannot trigger QThread destruction aborts."""

import asyncio
import threading
import time

from .qt_compat import QObject, Signal


class DaemonWorker(QObject):
    """Qt-signalling worker backed by a daemon Python thread.

    A ``QThread`` object must outlive its running native thread; deleting a
    settings dialog while its network request is still unwinding can otherwise
    abort the entire IDA process. A Python thread retains its bound worker for
    the duration of ``run()``, so closing the UI cannot destroy the worker out
    from under an in-flight request.
    """

    finished = Signal()

    def __init__(self):
        super().__init__()
        self._thread = None
        self._interruption_requested = threading.Event()
        self._async_lock = threading.Lock()
        self._async_loop = None
        self._async_task = None

    def start(self):
        """Start the worker once."""
        if self.isRunning():
            return
        self._thread = threading.Thread(
            target=self._bootstrap,
            name=type(self).__name__,
            daemon=True,
        )
        self._thread.start()

    def _bootstrap(self):
        try:
            self.run()
        finally:
            try:
                self.finished.emit()
            except RuntimeError:
                # IDA may already be tearing down its Qt objects.
                pass

    def run(self):
        raise NotImplementedError

    def isRunning(self):
        return self._thread is not None and self._thread.is_alive()

    def requestInterruption(self):
        self._interruption_requested.set()
        with self._async_lock:
            loop = self._async_loop
            task = self._async_task

        if loop is not None and task is not None and loop.is_running():
            try:
                loop.call_soon_threadsafe(task.cancel)
            except RuntimeError:
                # The worker finished and closed the loop after the snapshot.
                pass

    def isInterruptionRequested(self):
        return self._interruption_requested.is_set()

    def quit(self):
        self.requestInterruption()

    def wait(self, timeout_ms=None):
        thread = self._thread
        if thread is None:
            return True
        if thread is threading.current_thread():
            return False

        timeout = None if timeout_ms is None else max(0, timeout_ms) / 1000.0
        thread.join(timeout)
        return not thread.is_alive()

    def _set_async_task(self, loop, task):
        with self._async_lock:
            self._async_loop = loop
            self._async_task = task

        if self.isInterruptionRequested():
            task.cancel()

    def _clear_async_task(self):
        with self._async_lock:
            self._async_loop = None
            self._async_task = None

    def run_async_task(self, loop, task, timeout_seconds):
        """Run an asyncio task with bounded, cooperative cancellation checks."""
        deadline = time.monotonic() + timeout_seconds
        while not task.done():
            if self.isInterruptionRequested():
                task.cancel()

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                task.cancel()
                loop.run_until_complete(asyncio.gather(task, return_exceptions=True))
                raise asyncio.TimeoutError

            loop.run_until_complete(
                asyncio.wait({task}, timeout=min(0.1, remaining))
            )

        return task.result()
