import os
import string
from enum import Enum
from typing import Any, override

from internalapi.sensor.collector_pb2 import ProcessSignal
from internalapi.sensor.sfa_pb2 import FileActivity


def extract_container_id(cgroup: str) -> str:
    if (scope_idx := cgroup.rfind('.scope')) != -1:
        cgroup = cgroup[:scope_idx]

    if not cgroup or len(cgroup) < 65:
        return ''

    cgroup = cgroup[-65:]
    if cgroup[0] not in ['/', '-']:
        return ''

    cgroup = cgroup[1:]
    if all(c in string.hexdigits for c in cgroup):
        return cgroup[:12]
    else:
        return ''


class EventType(Enum):
    """Enumeration for different types of file activity events."""
    OPEN = 1
    CREATION = 2


class Process:
    """
    Represents a process with its attributes.
    """

    def __init__(self, pid: int | None = None):
        self._pid: int = pid if pid is not None else os.getpid()
        proc_dir = os.path.join('/proc', str(self._pid))

        with open(os.path.join(proc_dir, 'status'), 'r') as f:
            def get_id(line: str, wanted_id: str) -> int | None:
                if line.startswith(f'{wanted_id}:'):
                    parts = line.split()
                    if len(parts) > 2:
                        return int(parts[1])
                return None

            for line in f.readlines():
                if (uid := get_id(line, 'Uid')) is not None:
                    self._uid: int = uid
                elif (gid := get_id(line, 'Gid')) is not None:
                    self._gid: int = gid

        self._exe_path: str = os.path.realpath(os.path.join(proc_dir, 'exe'))

        with open(os.path.join(proc_dir, 'cmdline'), 'rb') as f:
            content = f.read(4096)
            args = [arg.decode('utf-8')
                    for arg in content.split(b'\x00') if arg]
            self._args: str = ' '.join(args)

        with open(os.path.join(proc_dir, 'comm'), 'r') as f:
            self._name: str = f.read().strip()

        with open(os.path.join(proc_dir, 'cgroup'), 'r') as f:
            self._container_id: str = extract_container_id(f.read())

        with open(os.path.join(proc_dir, 'loginuid'), 'r') as f:
            self._loginuid: int = int(f.read())

    @property
    def uid(self) -> int:
        return self._uid

    @property
    def gid(self) -> int:
        return self._gid

    @property
    def pid(self) -> int:
        return self._pid

    @property
    def exe_path(self) -> str:
        return self._exe_path

    @property
    def args(self) -> str:
        return self._args

    @property
    def name(self) -> str:
        return self._name

    @property
    def container_id(self) -> str:
        return self._container_id

    @property
    def loginuid(self) -> int:
        return self._loginuid

    @override
    def __eq__(self, other: Any) -> bool:
        if isinstance(other, ProcessSignal):
            return (
                self.uid == other.uid and
                self.gid == other.gid and
                self.pid == other.pid and
                self.exe_path == other.exec_file_path and
                self.args == other.args and
                self.name == other.name and
                self.container_id == other.container_id and
                self.loginuid == other.login_uid
            )
        raise NotImplementedError

    @override
    def __str__(self) -> str:
        return (f'Process(uid={self.uid}, gid={self.gid}, pid={self.pid}, '
                f'exe_path={self.exe_path}, args={self.args}, '
                f'name={self.name}, container_id={self.container_id}, '
                f'loginuid={self.loginuid}')


class Event:
    """
    Represents a file activity event, associating a process with an
    event type and a file.
    """

    def __init__(self,
                 process: Process,
                 event_type: EventType,
                 file: str):
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
            if self.process != other.process or self.event_type.name.lower() != other.WhichOneof('file'):
                return False

            if self.event_type == EventType.CREATION:
                return self.file == other.creation.activity.path
            elif self.event_type == EventType.OPEN:
                return self.file == other.open.activity.path
            return False
        raise NotImplementedError

    @override
    def __str__(self) -> str:
        return (f'Event(event_type={self.event_type.name}, '
                f'process={self.process}, file="{self.file}")')
