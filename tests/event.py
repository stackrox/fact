from enum import Enum
from typing import Any, override

from internalapi.sensor.collector_pb2 import ProcessSignal
from internalapi.sensor.sfa_pb2 import FileActivity


class EventType(Enum):
    OPEN = 1


class Process:
    def __init__(self,
                 uid: int = 0,
                 name: str = '',
                 container_id: str = '',
                 gid: int = 0,
                 pid: int = 0):
        self._uid: int = uid
        self._name: str = name
        self._container_id: str = container_id
        self._gid: int = gid
        self._pid: int = pid

    @property
    def uid(self) -> int:
        return self._uid

    @property
    def name(self) -> str:
        return self._name

    @property
    def container_id(self) -> str:
        return self._container_id

    @property
    def gid(self) -> int:
        return self._gid

    @property
    def pid(self) -> int:
        return self._pid

    @override
    def __eq__(self, other: Any) -> bool:
        if isinstance(other, ProcessSignal):
            return (
                self.container_id == other.container_id and
                self.uid == other.uid and
                self.gid == other.gid and
                self.pid == other.pid and
                self.name == other.name
            )
        raise NotImplementedError

    @override
    def __str__(self) -> str:
        return (f'Process(uid={self.uid}, name="{self.name}", '
                f'container_id="{self.container_id}", gid={self.gid}, '
                f'pid={self.pid})')


class Event:
    def __init__(self,
                 process: Process,
                 event_type: EventType = EventType.OPEN,
                 file: str = ''):
        self._type: EventType = event_type
        self._process: Process = process
        self._file: str = file

    @property
    def event_type(self) -> EventType:
        return self._type

    @property
    def process(self) -> Process:
        return self._process

    @property
    def file(self) -> str:
        return self._file

    @override
    def __eq__(self, other: Any) -> bool:
        if isinstance(other, FileActivity):
            return (
                self.process == other.process and
                self.event_type.name.lower() == other.WhichOneof('file') and
                self.file == other.open.activity.path
            )
        raise NotImplementedError

    @override
    def __str__(self) -> str:
        return (f'Event(event_type={self.event_type.name}, '
                f'process={self.process}, file="{self.file}")')
