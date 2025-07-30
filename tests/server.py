from concurrent import futures
from collections import deque
from threading import Event

from google.protobuf.json_format import MessageToJson
import grpc

from internalapi.sensor import sfa_iservice_pb2_grpc


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
        sfa_iservice_pb2_grpc.FileActivityService.__init__(self)
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
        self.queue = deque()
        self.running = Event()

    def Communicate(self, request_iterator, context):
        """
        GRPC method to receive a stream of file activity requests.
        Appends each incoming request to an internal queue.
        """
        for req in request_iterator:
            self.queue.append(req)

    def serve(self):
        """
        Starts the GRPC server, listening on port 0.0.0.0:9999.
        Sets the running event once the server starts.
        """
        sfa_iservice_pb2_grpc.add_FileActivityServiceServicer_to_server(
            self, self.server
        )
        self.server.add_insecure_port('0.0.0.0:9999')
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
