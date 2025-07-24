#!/usr/bin/env python3

from concurrent import futures
import json
import logging

import grpc
from google.protobuf.json_format import MessageToJson

from internalapi.sensor import sfa_iservice_pb2_grpc


class FileActivityServicer(sfa_iservice_pb2_grpc.FileActivityServiceServicer):
    def Communicate(self, request_iterator, context):
        for req in request_iterator:
            print(MessageToJson(req))


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    sfa_iservice_pb2_grpc.add_FileActivityServiceServicer_to_server(
        FileActivityServicer(), server
    )
    server.add_insecure_port("0.0.0.0:9999")
    server.start()
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        server.stop(5)


if __name__ == '__main__':
    logging.basicConfig()
    serve()
