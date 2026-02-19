import os
from re import Pattern
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
    UNLINK = 3
    PERMISSION = 4
    OWNERSHIP = 5


class Process:
    """
    Represents a process with its attributes.
    """

    def __init__(self,
                 pid: int | None,
                 uid: int,
                 gid: int,
                 exe_path: str,
                 args: str,
                 name: str,
                 container_id: str,
                 loginuid: int):
        self._pid: int | None = pid
        self._uid: int = uid
        self._gid: int = gid
        self._exe_path: str = exe_path
        self._args: str = args
        self._name: str = name
        self._container_id: str = container_id
        self._loginuid: int = loginuid

    @classmethod
    def from_proc(cls, pid: int | None = None):
        pid: int = pid if pid is not None else os.getpid()
        proc_dir = os.path.join('/proc', str(pid))

        uid = 0
        gid = 0
        with open(os.path.join(proc_dir, 'status'), 'r') as f:
            def get_id(line: str, wanted_id: str) -> int | None:
                if line.startswith(f'{wanted_id}:'):
                    parts = line.split()
                    if len(parts) > 2:
                        return int(parts[1])
                return None

            for line in f.readlines():
                if (id := get_id(line, 'Uid')) is not None:
                    uid = id
                elif (id := get_id(line, 'Gid')) is not None:
                    gid = id

        exe_path = os.path.realpath(os.path.join(proc_dir, 'exe'))

        with open(os.path.join(proc_dir, 'cmdline'), 'rb') as f:
            content = f.read(4096)
            args = [arg.decode('utf-8')
                    for arg in content.split(b'\x00') if arg]
        args = ' '.join(args)

        with open(os.path.join(proc_dir, 'comm'), 'r') as f:
            name = f.read().strip()

        with open(os.path.join(proc_dir, 'cgroup'), 'r') as f:
            container_id = extract_container_id(f.read())

        with open(os.path.join(proc_dir, 'loginuid'), 'r') as f:
            loginuid = int(f.read())

        return Process(pid=pid,
                       uid=uid,
                       gid=gid,
                       exe_path=exe_path,
                       args=args,
                       name=name,
                       container_id=container_id,
                       loginuid=loginuid)

    @classmethod
    def in_container(cls,
                     exe_path: str,
                     args: str,
                     name: str,
                     container_id: str):
        return Process(pid=None,
                       uid=0,
                       gid=0,
                       loginuid=pow(2, 32)-1,
                       exe_path=exe_path,
                       args=args,
                       name=name,
                       container_id=container_id)

    @property
    def uid(self) -> int:
        return self._uid

    @property
    def gid(self) -> int:
        return self._gid

    @property
    def pid(self) -> int | None:
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

    def diff(self, other: ProcessSignal) -> dict | None:
        """
        Compare this Process with a ProcessSignal protobuf message.

        Args:
            other: ProcessSignal protobuf message to compare against

        Returns:
            None if identical, dict of differences if not matching

        Raises:
            NotImplementedError: If other is not a ProcessSignal
        """
        if not isinstance(other, ProcessSignal):
            raise NotImplementedError(
                f'Cannot compare Process with {type(other)}')

        diff = {}

        # Compare each field
        if self.pid is not None:
            Event._diff_field(diff, 'pid', self.pid, other.pid)

        Event._diff_field(diff, 'uid', self.uid, other.uid)
        Event._diff_field(diff, 'gid', self.gid, other.gid)
        Event._diff_field(diff, 'exe_path',
                          self.exe_path, other.exec_file_path)
        Event._diff_field(diff, 'args', self.args, other.args)
        Event._diff_field(diff, 'name', self.name, other.name)
        Event._diff_field(diff, 'container_id',
                          self.container_id, other.container_id)
        Event._diff_field(diff, 'loginuid',
                          self.loginuid, other.login_uid)

        return diff if diff else None

    @override
    def __str__(self) -> str:
        return (f'Process(uid={self.uid}, gid={self.gid}, pid={self.pid}, '
                f'exe_path={self.exe_path}, args={self.args}, '
                f'name={self.name}, container_id={self.container_id}, '
                f'loginuid={self.loginuid})')


def _diff_path(expected: str | Pattern[str], actual: str) -> dict | None:
    """
    Compare paths with regex pattern support.

    Returns:
        (field_name, diff_dict) if paths don't match, None if they match
    """
    if isinstance(expected, Pattern):
        if not expected.match(actual):
            return {
                'expected': f'{expected}',
                'actual': actual
            }
    elif expected != actual:
        return {
            'expected': expected,
            'actual': actual
        }
    return None


class Event:
    """
    Represents a file activity event, associating a process with an
    event type and a file.
    """

    def __init__(self,
                 process: Process,
                 event_type: EventType,
                 file: str | Pattern[str],
                 host_path: str | Pattern[str] = '',
                 mode: int | None = None,
                 owner_uid: int | None = None,
                 owner_gid: int | None = None,):
        self._type: EventType = event_type
        self._process: Process = process
        self._file: str | Pattern[str] = file
        self._host_path: str | Pattern[str] = host_path
        self._mode: int | None = mode
        self._owner_uid: int | None = owner_uid
        self._owner_gid: int | None = owner_gid

    @property
    def event_type(self) -> EventType:
        return self._type

    @property
    def process(self) -> Process:
        return self._process

    @property
    def file(self) -> str | Pattern[str]:
        return self._file

    @property
    def host_path(self) -> str | Pattern[str]:
        return self._host_path

    @property
    def mode(self) -> int | None:
        return self._mode

    @property
    def owner_uid(self) -> int | None:
        return self._owner_uid

    @property
    def owner_gid(self) -> int | None:
        return self._owner_gid

    @classmethod
    def _diff_field(cls, diff, name, expected, actual):
        if expected != actual:
            diff[name] = {
                'expected': expected,
                'actual': actual,
            }

    def diff(self, other: FileActivity) -> dict | None:
        """
        Compare this Event with a FileActivity protobuf message.

        Args:
            other: FileActivity protobuf message to compare against

        Returns:
            None if identical, dict of differences if not matching

        Raises:
            NotImplementedError: If other is not a FileActivity
        """
        if not isinstance(other, FileActivity):
            raise NotImplementedError(
                f'Cannot compare Event with {type(other)}')

        diff = {}

        # Check process differences first
        process_diff = self.process.diff(other.process)
        if process_diff is not None:
            diff['process'] = process_diff

        # Check event type
        event_type_expected = self.event_type.name.lower()
        event_type_actual = other.WhichOneof('file')

        Event._diff_field(diff, 'event_type',
                          event_type_expected, event_type_actual)
        if event_type_expected != event_type_actual:
            return diff

        # Get the appropriate event field based on type
        event_field = getattr(other, event_type_expected)

        # Compare file and host_path (common to all event types)
        # All event types have .activity.path and .activity.host_path except they're accessed differently
        file_diff = _diff_path(self.file, event_field.activity.path)
        if file_diff is not None:
            diff['file'] = file_diff

        host_path_diff = _diff_path(self.host_path,
                                    event_field.activity.host_path)
        if host_path_diff is not None:
            diff['host_path'] = host_path_diff

        if self.event_type == EventType.PERMISSION:
            Event._diff_field(diff, 'mode', self.mode, event_field.mode)
        elif self.event_type == EventType.OWNERSHIP:
            Event._diff_field(diff, 'owner_uid',
                              self.owner_uid, event_field.uid)
            Event._diff_field(diff, 'owner_gid',
                              self.owner_gid, event_field.gid)

        return diff if diff else None

    @override
    def __str__(self) -> str:
        s = (f'Event(event_type={self.event_type.name}, '
             f'process={self.process}, file="{self.file}", '
             f'host_path="{self.host_path}"')

        if self.event_type == EventType.PERMISSION:
            s += f', mode={self.mode}'

        if self.event_type == EventType.OWNERSHIP:
            s += f', owner=(uid={self.owner_uid}, gid={self.owner_gid})'

        s += ')'

        return s
