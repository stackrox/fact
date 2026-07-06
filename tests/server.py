from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Iterable
from concurrent import futures
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Event as ThreadingEvent
from threading import Thread
from time import sleep
from typing import TYPE_CHECKING, Any

import grpc
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
    ExportLogsServiceRequest,
    ExportLogsServiceResponse,
)

import utils
from event import (
    ACL_TAG_GROUP,
    ACL_TAG_GROUP_OBJ,
    ACL_TAG_MASK,
    ACL_TAG_OTHER,
    ACL_TAG_USER,
    ACL_TAG_USER_OBJ,
    ACL_TYPE_ACCESS,
    ACL_TYPE_DEFAULT,
    Event,
    EventType,
    Process,
)
from internalapi.sensor import sfa_iservice_pb2_grpc
from internalapi.sensor.sfa_pb2 import FileActivity

if TYPE_CHECKING:
    from opentelemetry.proto.common.v1.common_pb2 import AnyValue, KeyValue
    from opentelemetry.proto.logs.v1.logs_pb2 import LogRecord

EVENT_TYPE_MAP: dict[str, EventType] = {
    'open': EventType.OPEN,
    'creation': EventType.CREATION,
    'unlink': EventType.UNLINK,
    'permission': EventType.PERMISSION,
    'ownership': EventType.OWNERSHIP,
    'rename': EventType.RENAME,
    'xattr_set': EventType.XATTR_SET,
    'xattr_remove': EventType.XATTR_REMOVE,
    'acl': EventType.ACL,
}


# Mapping from friendly skip names to event type.
SKIP_EVENT_TYPES: dict[str, tuple[EventType, ...]] = {
    'xattr': (EventType.XATTR_SET, EventType.XATTR_REMOVE),
    'acl': (EventType.ACL,),
}

DEFAULT_SKIP = ('xattr', 'acl')

ACL_TAG_MAP: dict[str, int] = {
    'user_obj': ACL_TAG_USER_OBJ,
    'user': ACL_TAG_USER,
    'group_obj': ACL_TAG_GROUP_OBJ,
    'group': ACL_TAG_GROUP,
    'mask': ACL_TAG_MASK,
    'other': ACL_TAG_OTHER,
}

ACL_TYPE_MAP: dict[str, int] = {
    'access': ACL_TYPE_ACCESS,
    'default': ACL_TYPE_DEFAULT,
}


class EventServer(ABC):
    """Base class for event-receiving test servers."""

    def __init__(self):
        self.queue: deque[Event] = deque()
        self.running = ThreadingEvent()
        self.executor = futures.ThreadPoolExecutor(max_workers=2)

    @property
    @abstractmethod
    def output_mode(self) -> str: ...

    @abstractmethod
    def serve(self) -> None: ...

    @abstractmethod
    def stop(self) -> None: ...

    def get_next(self) -> Event | None:
        """
        Retrieve and remove the next event from the queue.
        Returns None if the queue is empty.
        """
        if self.is_empty():
            return None
        return self.queue.popleft()

    def is_empty(self) -> bool:
        """Check if the internal queue of events is empty."""
        return len(self.queue) == 0

    def is_running(self) -> bool:
        """Check if the server is currently running."""
        return self.running.is_set()

    def _wait_events(
        self,
        events: list[Event],
        strict: bool,
        skip_oneof_names: frozenset[EventType],
        cancel: ThreadingEvent,
    ):
        while self.is_running() and not cancel.is_set():
            msg = self.get_next()
            if msg is None:
                sleep(0.5)
                continue

            print(f'Got event: {msg}')

            if msg.event_type in skip_oneof_names:
                continue

            diff = events[0].diff(msg)
            if diff is None:
                events.pop(0)
                if len(events) == 0:
                    return
            elif strict:
                raise ValueError(json.dumps(diff, indent=4, default=str))

    def wait_events(
        self,
        events: list[Event],
        strict: bool = True,
        skip: tuple[str, ...] = DEFAULT_SKIP,
    ):
        """
        Continuously checks the server for incoming events until the
        specified events are found.

        Args:
            events: The events to search for.
            strict: Fail if an unexpected event is detected.
            skip: Event categories to silently ignore (e.g. 'xattr',
                'acl'). Pass an empty tuple to receive all events.

        Raises:
            TimeoutError: If the required events are not found in 5 seconds.
        """
        skip_oneof_names = frozenset(
            name
            for key in skip
            for name in (
                SKIP_EVENT_TYPES[key]
                if key in SKIP_EVENT_TYPES
                else (EVENT_TYPE_MAP[key],)
            )
        )
        print('Waiting for events:', *events, sep='\n')
        cancel = ThreadingEvent()
        fs = self.executor.submit(
            self._wait_events,
            events,
            strict,
            skip_oneof_names,
            cancel,
        )
        try:
            fs.result(timeout=5)
        except TimeoutError:
            raise
        finally:
            cancel.set()


class GrpcServer(
    EventServer, sfa_iservice_pb2_grpc.FileActivityServiceServicer
):
    """gRPC server for the File Activity Service."""

    def __init__(self):
        super().__init__()
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))

    @property
    def output_mode(self) -> str:
        return 'grpc'

    @staticmethod
    def _translate(msg: FileActivity) -> Event | None:
        """Translate a FileActivity protobuf message into an Event."""
        oneof = msg.WhichOneof('file')
        if oneof is None or oneof not in EVENT_TYPE_MAP:
            return None

        event_type = EVENT_TYPE_MAP[oneof]
        field = getattr(msg, oneof)

        proc = msg.process
        process = Process(
            pid=proc.pid,
            uid=proc.uid,
            gid=proc.gid,
            exe_path=proc.exec_file_path,
            args=proc.args,
            name=proc.name,
            container_id=proc.container_id,
            loginuid=proc.login_uid,
        )

        if event_type != EventType.RENAME:
            file_path = field.activity.path
            host_path = field.activity.host_path
        else:
            file_path = field.new.path
            host_path = field.new.host_path

        kwargs: dict[str, Any] = {
            'file': file_path,
            'host_path': host_path,
        }

        if event_type == EventType.RENAME:
            kwargs['old_file'] = field.old.path
            kwargs['old_host_path'] = field.old.host_path
        elif event_type == EventType.PERMISSION:
            kwargs['mode'] = field.mode
        elif event_type == EventType.OWNERSHIP:
            kwargs['owner_uid'] = field.uid
            kwargs['owner_gid'] = field.gid
        elif event_type in (EventType.XATTR_SET, EventType.XATTR_REMOVE):
            kwargs['xattr_name'] = field.xattr_name
        elif event_type == EventType.ACL:
            kwargs['acl_type'] = field.acl_type
            kwargs['acl_entries'] = [
                {
                    'tag': e.tag,
                    'perm': e.perm,
                    'id': e.id,
                }
                for e in field.entries
            ]

        return Event(
            process=process,
            event_type=event_type,
            **kwargs,
        )

    def Communicate(self, request_iterator: Any, context: Any):
        """
        gRPC method to receive a stream of file activity requests.
        Translates each FileActivity protobuf into an Event and
        appends it to the queue.
        """
        for req in request_iterator:
            event = self._translate(req)
            if event is not None:
                self.queue.append(event)

    def serve(self, addr: str = '0.0.0.0:9999'):
        """Start the gRPC server on the given address."""
        sfa_iservice_pb2_grpc.add_FileActivityServiceServicer_to_server(
            self,
            self.server,
        )
        self.server.add_insecure_port(addr)
        self.server.start()
        self.running.set()

    def stop(self):
        """Stop the gRPC server."""
        self.server.stop(1)
        self.running.clear()


class OtlpServer(EventServer):
    """HTTP server that receives OTLP/HTTP binary protobuf log exports."""

    def __init__(self):
        super().__init__()
        self._httpd: HTTPServer | None = None
        self._thread: Thread | None = None

    @property
    def output_mode(self) -> str:
        return 'otlp'

    @staticmethod
    def _anyvalue_to_python(value: AnyValue) -> Any:
        """Convert an OTLP AnyValue protobuf to a native Python type."""
        kind = value.WhichOneof('value')
        if kind == 'string_value':
            return value.string_value
        if kind == 'int_value':
            return value.int_value
        if kind == 'bool_value':
            return value.bool_value
        if kind == 'double_value':
            return value.double_value
        if kind == 'kvlist_value':
            return OtlpServer._kvlist_to_dict(value.kvlist_value.values)
        if kind == 'array_value':
            return [
                OtlpServer._anyvalue_to_python(v)
                for v in value.array_value.values
            ]
        if kind == 'bytes_value':
            return value.bytes_value
        return None

    @staticmethod
    def _kvlist_to_dict(kvs: Iterable[KeyValue]) -> dict[str, Any]:
        """Convert a list of OTLP KeyValue pairs to a Python dict."""
        return {kv.key: OtlpServer._anyvalue_to_python(kv.value) for kv in kvs}

    @staticmethod
    def _acl_entry_translate(entry: dict[str, Any]) -> dict[str, Any]:
        return {
            'tag': ACL_TAG_MAP.get(entry['tag'], -1),
            'perm': entry['perm'],
            'id': entry.get('id', 0xFFFFFFFF),
        }

    @staticmethod
    def _translate(record: LogRecord) -> Event | None:
        """
        Translate an OTLP LogRecord into an Event.

        Returns None for event types that only exist in the OTLP
        schema (mkdir, rmdir) or are otherwise unrecognised.
        """
        attrs = OtlpServer._kvlist_to_dict(record.attributes)

        file_data = attrs.get('file', {})
        event_type_str = file_data.get('event_type', '')

        if event_type_str not in EVENT_TYPE_MAP:
            return None

        event_type = EVENT_TYPE_MAP[event_type_str]

        proc_data = attrs.get('process', {})
        args_list = proc_data.get('args', [])
        args = (
            utils.rust_style_join(args_list)
            if isinstance(args_list, list)
            else str(args_list)
        )

        process = Process(
            pid=proc_data.get('pid', 0),
            uid=proc_data.get('uid', 0),
            gid=proc_data.get('gid', 0),
            exe_path=proc_data.get('exe_path', ''),
            args=args,
            name=proc_data.get('comm', ''),
            container_id=proc_data.get('container_id', ''),
            loginuid=proc_data.get('login_uid', 0),
        )

        kwargs: dict[str, Any] = {
            'file': file_data.get('filename', ''),
            'host_path': file_data.get('host_path', ''),
        }
        if event_type == EventType.RENAME:
            old = file_data.get('old', {})
            kwargs['old_file'] = old.get('filename', '')
            kwargs['old_host_path'] = old.get('host_path', '')
        elif event_type == EventType.PERMISSION:
            kwargs['mode'] = file_data.get('new_mode')
        elif event_type == EventType.OWNERSHIP:
            kwargs['owner_uid'] = file_data.get('new_uid')
            kwargs['owner_gid'] = file_data.get('new_gid')
        elif event_type in (EventType.XATTR_SET, EventType.XATTR_REMOVE):
            kwargs['xattr_name'] = file_data.get('xattr_name')
        elif event_type == EventType.ACL:
            kwargs['acl_type'] = ACL_TYPE_MAP.get(file_data.get('acl_type'))
            kwargs['acl_entries'] = [
                OtlpServer._acl_entry_translate(entry)
                for entry in file_data.get('entries', [])
            ]

        return Event(
            process=process,
            event_type=event_type,
            **kwargs,
        )

    def serve(self, addr: str = '0.0.0.0', port: int = 4318):
        """
        Start the HTTP server on the given address and port.

        Handles POST /v1/logs with OTLP binary protobuf payloads.
        Each log record is translated into an Event and appended
        to the queue. Events with types not present in the gRPC
        schema (mkdir, rmdir) are silently dropped.
        """
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path != '/v1/logs':
                    self.send_error(404)
                    return

                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length)

                request = ExportLogsServiceRequest()
                request.ParseFromString(body)

                for resource_logs in request.resource_logs:
                    for scope_logs in resource_logs.scope_logs:
                        for record in scope_logs.log_records:
                            event = OtlpServer._translate(record)
                            if event is not None:
                                parent.queue.append(event)

                response = ExportLogsServiceResponse()
                response_bytes = response.SerializeToString()

                self.send_response(200)
                self.send_header('Content-Type', 'application/x-protobuf')
                self.send_header('Content-Length', str(len(response_bytes)))
                self.end_headers()
                self.wfile.write(response_bytes)

            def log_message(self, format: str, *args: Any):
                pass

        self._httpd = HTTPServer((addr, port), Handler)
        self._thread = Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        self.running.set()

    def stop(self):
        """Stop the HTTP server and close its socket."""
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self.running.clear()
