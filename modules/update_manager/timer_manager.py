from threading import Timer
import asyncio

class InfiniteTimer:
    """
    Timer to update Threat Intelligence Files when Slips starts
    """

    def __init__(self, seconds, target):
        self.timer_running = False
        self.target_running = False
        self.seconds = seconds
        self.target = target
        self.thread = None

    def _handle_target(self):
        self.target_running = True
        asyncio.run(self.target())
        self.target_running = False
        self._start_timer()

    def _start_timer(self):
        if (
            self.timer_running
        ):
            self.thread = Timer(self.seconds, self._handle_target)
            self.thread.start()

    def start(self):
        if not self.timer_running and not self.target_running:
            self.timer_running = True
            self._start_timer()

    def cancel(self):
        if self.thread is not None:
            self.timer_running = (
                False
            )
            self.thread.cancel()
