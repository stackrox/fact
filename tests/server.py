from __future__ import annotations

import json
from collections import deque
from concurrent import futures
from threading import Event as ThreadingEvent
from time import sleep
from typing import TYPE_CHECKING, Any

import grpc

from internalapi.sensor import sfa_iservice_pb2_grpc

if TYPE_CHECKING:
    from event import Event


class FileActivityService(sfa_iservice_pb2_grpc.FileActivityServiceServicer):
    """
    GRPC server for the File Activity Service.
    This service allows clients to communicate file activity events.
    """

    def __init__(self):
        """
        Initializes the FileActivityService.
        Sets up the GRPC server, a queue for incoming requests, and an
        event for other threads to know when the server stops.
        """
        super().__init__()
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
        self.queue = deque()
        self.running = ThreadingEvent()
        self.executor = futures.ThreadPoolExecutor(max_workers=2)

    def Communicate(self, request_iterator: Any, context: Any):
        """
        GRPC method to receive a stream of file activity requests.
        Appends each incoming request to an internal queue.
        """
        for req in request_iterator:
            self.queue.append(req)

    def serve(self, addr: str = '0.0.0.0:9999'):
        """
        Starts the GRPC server.
        Sets the running event once the server starts.
        """
        sfa_iservice_pb2_grpc.add_FileActivityServiceServicer_to_server(
            self,
            self.server,
        )
        self.server.add_insecure_port(addr)
        self.server.start()
        self.running.set()

    def stop(self):
        """
        Stops the GRPC server.
        Marks the server as not running once it is done.
        """
        self.server.stop(1)
        self.running.clear()

    def get_next(self):
        """
        Retrieves and removes the next file activity event from the
        queue.
        Returns None if the queue is empty.
        """
        if self.is_empty():
            return None
        return self.queue.popleft()

    def is_empty(self):
        """
        Checks if the internal queue of file activity events is empty.
        Returns:
            bool: True if the queue is empty, False otherwise.
        """
        return len(self.queue) == 0

    def is_running(self):
        """
        Checks if the GRPC server is currently running.
        Returns:
            bool: True if the server is running, False otherwise.
        """
        return self.running.is_set()

    def _wait_events(
        self,
        events: list[Event],
        strict: bool,
        cancel: ThreadingEvent,
    ):
        while self.is_running() and not cancel.is_set():
            msg = self.get_next()
            if msg is None:
                sleep(0.5)
                continue

            print(f'Got event: {msg}')

            # Check if msg matches the next expected event
            diff = events[0].diff(msg)
            if diff is None:
                events.pop(0)
                if len(events) == 0:
                    return
            elif strict:
                # Container events are fully controlled by the test,
                # so any mismatch is a real failure. Node events may
                # include system noise (e.g. SELinux xattr changes)
                # that the test cannot predict, so they are skipped.
                is_container_event = bool(msg.process.container_id)
                if is_container_event:
                    raise ValueError(json.dumps(diff, indent=4))

    def wait_events(self, events: list[Event], strict: bool = True):
        """
        Continuously checks the server for incoming events until the
        specified events are found.

        Args:
            events (list['Event']): The events to search for.
            strict (bool): Fail if an unexpected event is detected.

        Raises:
            TimeoutError: If the required events are not found in 5 seconds.
        """
        print('Waiting for events:', *events, sep='\n')
        cancel = ThreadingEvent()
        fs = self.executor.submit(self._wait_events, events, strict, cancel)
        try:
            fs.result(timeout=5)
        except TimeoutError:
            raise
        finally:
            cancel.set()
