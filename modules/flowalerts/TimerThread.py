import threading


class TimerThread(threading.Thread):
    """Thread that executes 1 task after N seconds. Only to run the process_global_data."""

    def __init__(self, interval, function, parameters):
        threading.Thread.__init__(self)
        self._finished = threading.Event()
        self._interval = interval
        self.function = function
        self.parameters = parameters

    def shutdown(self):
        """Stop this thread"""
        self._finished.set()

    def run(self):
        try:
            if self._finished.isSet():
                return True
            self._finished.wait(self._interval)

            self.task()
            return True

        except KeyboardInterrupt:
            return True

    def task(self):
        self.function(*self.parameters)
