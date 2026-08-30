"""Regression tests for cancellable settings workers."""

import asyncio
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.daemon_worker import DaemonWorker


class TestSettingsWorkers(unittest.TestCase):
    def test_async_worker_cancels_without_destroying_a_qthread(self):
        """Closing settings can cancel a pending async test safely."""
        started = threading.Event()

        class AsyncWorker(DaemonWorker):
            def run(self):
                loop = asyncio.new_event_loop()
                task = loop.create_task(self.wait_forever())
                self._set_async_task(loop, task)
                try:
                    self.run_async_task(loop, task, 30)
                except asyncio.CancelledError:
                    pass
                finally:
                    self._clear_async_task()
                    loop.close()

            async def wait_forever(self):
                started.set()
                await asyncio.Event().wait()

        worker = AsyncWorker()
        worker.start()

        self.assertTrue(started.wait(1.0))
        worker.requestInterruption()
        self.assertTrue(worker.wait(1000))
        self.assertFalse(worker.isRunning())


if __name__ == "__main__":
    unittest.main()
