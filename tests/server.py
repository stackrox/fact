from concurrent import futures
from collections import deque
from threading import Event

from google.protobuf.json_format import MessageToJson
import grpc

from internalapi.sensor import sfa_iservice_pb2_grpc


class FileActivityService(sfa_iservice_pb2_grpc.FileActivityServiceServicer):
    def __init__(self):
        sfa_iservice_pb2_grpc.FileActivityService.__init__(self)
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
        self.queue = deque()
        self.running = Event()

    def Communicate(self, request_iterator, context):
        for req in request_iterator:
            self.queue.append(req)

    def serve(self):
        sfa_iservice_pb2_grpc.add_FileActivityServiceServicer_to_server(
            self, self.server
        )
        self.server.add_insecure_port('0.0.0.0:9999')
        self.server.start()
        self.running.set()

    def stop(self):
        self.server.stop(1)
        self.running.clear()

    def get_next(self):
        if self.is_empty():
            return None
        return self.queue.popleft()

    def is_empty(self):
        return len(self.queue) == 0

    def is_running(self):
        return self.running.is_set()
