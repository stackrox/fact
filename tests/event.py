from __future__ import annotations

import os
import string
from enum import Enum
from re import Pattern
from typing import Any

try:
    from typing import override  # type: ignore[reportAssignmentType]
except ImportError:

    def override(func):  # type: ignore[reportMissingParameterType]
        return func


import utils


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
    RENAME = 6
    XATTR_SET = 7
    XATTR_REMOVE = 8
    ACL = 9


# POSIX ACL type values matching the AclType proto enum.
ACL_TYPE_ACCESS = 1
ACL_TYPE_DEFAULT = 2

# POSIX ACL tag values matching the AclTag proto enum.
ACL_TAG_USER_OBJ = 1
ACL_TAG_USER = 2
ACL_TAG_GROUP_OBJ = 3
ACL_TAG_GROUP = 4
ACL_TAG_MASK = 5
ACL_TAG_OTHER = 6


class Process:
    """
    Represents a process with its attributes.
    """

    def __init__(
        self,
        pid: int | None,
        uid: int,
        gid: int,
        exe_path: str,
        args: str,
        name: str,
        container_id: str,
        loginuid: int,
    ):
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
        pid = pid if pid is not None else os.getpid()
        proc_dir = os.path.join('/proc', str(pid))

        uid = 0
        gid = 0
        with open(os.path.join(proc_dir, 'status')) as f:

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
            args = [
                arg.decode('utf-8') for arg in content.split(b'\x00') if arg
            ]
        args = utils.rust_style_join(args)

        with open(os.path.join(proc_dir, 'comm')) as f:
            name = f.read().strip()

        with open(os.path.join(proc_dir, 'cgroup')) as f:
            container_id = extract_container_id(f.read())

        with open(os.path.join(proc_dir, 'loginuid')) as f:
            loginuid = int(f.read())

        return Process(
            pid=pid,
            uid=uid,
            gid=gid,
            exe_path=exe_path,
            args=args,
            name=name,
            container_id=container_id,
            loginuid=loginuid,
        )

    @classmethod
    def in_container(
        cls,
        exe_path: str,
        args: str,
        name: str,
        container_id: str,
    ):
        return Process(
            pid=None,
            uid=0,
            gid=0,
            loginuid=pow(2, 32) - 1,
            exe_path=exe_path,
            args=args,
            name=name,
            container_id=container_id,
        )

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

    def diff(self, other: Process) -> dict | None:
        """
        Compare this Process with another Process instance.

        PID comparison is skipped if self.pid is None.

        Args:
            other: Process instance to compare against.

        Returns:
            None if identical, dict of differences if not matching.
        """
        diff = {}

        if self.pid is not None:
            Event._diff_field(diff, 'pid', self.pid, other.pid)

        Event._diff_field(diff, 'uid', self.uid, other.uid)
        Event._diff_field(diff, 'gid', self.gid, other.gid)
        Event._diff_field(diff, 'exe_path', self.exe_path, other.exe_path)
        Event._diff_field(diff, 'args', self.args, other.args)
        Event._diff_field(diff, 'name', self.name, other.name)
        Event._diff_field(
            diff,
            'container_id',
            self.container_id,
            other.container_id,
        )
        Event._diff_field(diff, 'loginuid', self.loginuid, other.loginuid)

        return diff if diff else None

    @override
    def __str__(self) -> str:
        return (
            f'Process(uid={self.uid}, gid={self.gid}, pid={self.pid}, '
            f'exe_path={self.exe_path}, args={self.args}, '
            f'name={self.name}, container_id={self.container_id}, '
            f'loginuid={self.loginuid})'
        )


class Event:
    """
    Represents a file activity event, associating a process with an
    event type and a file.
    """

    def __init__(
        self,
        process: Process,
        event_type: EventType,
        file: str | Pattern[str],
        host_path: str | Pattern[str] = '',
        mode: int | None = None,
        owner_uid: int | None = None,
        owner_gid: int | None = None,
        old_file: str | Pattern[str] | None = None,
        old_host_path: str | Pattern[str] | None = None,
        xattr_name: str | None = None,
        acl_type: int | None = None,
        acl_entries: list[dict] | None = None,
    ):
        self._type: EventType = event_type
        self._process: Process = process
        self._file: str | Pattern[str] = file
        self._host_path: str | Pattern[str] = host_path
        self._mode: int | None = mode
        self._owner_uid: int | None = owner_uid
        self._owner_gid: int | None = owner_gid
        self._old_file: str | Pattern[str] | None = old_file
        self._old_host_path: str | Pattern[str] | None = old_host_path
        self._xattr_name: str | None = xattr_name
        self._acl_type: int | None = acl_type
        self._acl_entries: list[dict] | None = acl_entries

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

    @property
    def old_file(self) -> str | Pattern[str] | None:
        return self._old_file

    @property
    def old_host_path(self) -> str | Pattern[str] | None:
        return self._old_host_path

    @property
    def xattr_name(self) -> str | None:
        return self._xattr_name

    @property
    def acl_type(self) -> int | None:
        return self._acl_type

    @property
    def acl_entries(self) -> list[dict] | None:
        return self._acl_entries

    @classmethod
    def _diff_field(cls, diff: dict, name: str, expected: Any, actual: Any):
        if expected != actual:
            diff[name] = {
                'expected': expected,
                'actual': actual,
            }

    @classmethod
    def _diff_path(
        cls,
        diff: dict,
        name: str,
        expected: str | Pattern[str] | None,
        actual: str | Pattern[str] | None,
    ):
        """
        Compare paths with regex pattern support.

        When expected is a compiled regex pattern, actual must be a
        string that matches it. Otherwise a simple equality check is
        performed.
        """
        if isinstance(expected, Pattern):
            if not isinstance(actual, str) or not expected.match(actual):
                diff[name] = {'expected': f'{expected}', 'actual': actual}
        elif expected != actual:
            diff[name] = {'expected': expected, 'actual': actual}

    def diff(self, other: Event) -> dict | None:
        """
        Compare this Event with another Event instance.

        Both gRPC and OTLP servers translate their native messages
        into Event objects, so this method provides a single
        protocol-agnostic comparison path.

        Args:
            other: Event instance to compare against.

        Returns:
            None if identical, dict of differences if not matching.
        """
        diff = {}

        process_diff = self.process.diff(other.process)
        if process_diff is not None:
            diff['process'] = process_diff

        Event._diff_field(
            diff,
            'event_type',
            self.event_type,
            other.event_type,
        )
        if diff:
            return diff

        # Rename handling is a bit different to the rest, since it has
        # new and old paths.
        if self.event_type != EventType.RENAME:
            Event._diff_path(diff, 'file', self.file, other.file)
            Event._diff_path(diff, 'host_path', self.host_path, other.host_path)
        else:
            Event._diff_path(diff, 'new_file', self.file, other.file)
            Event._diff_path(
                diff, 'new_host_path', self.host_path, other.host_path
            )
            Event._diff_path(diff, 'old_file', self.old_file, other.old_file)
            Event._diff_path(
                diff, 'old_host_path', self.old_host_path, other.old_host_path
            )

        if self.event_type == EventType.PERMISSION:
            Event._diff_field(diff, 'mode', self.mode, other.mode)
        elif self.event_type == EventType.OWNERSHIP:
            Event._diff_field(
                diff, 'owner_uid', self.owner_uid, other.owner_uid
            )
            Event._diff_field(
                diff, 'owner_gid', self.owner_gid, other.owner_gid
            )
        elif self.event_type in (EventType.XATTR_SET, EventType.XATTR_REMOVE):
            Event._diff_field(
                diff, 'xattr_name', self.xattr_name, other.xattr_name
            )
        elif self.event_type == EventType.ACL:
            Event._diff_field(
                diff,
                'acl_type',
                self.acl_type,
                other.acl_type,
            )
            if self.acl_entries is not None:
                Event._diff_field(
                    diff,
                    'acl_entries',
                    self.acl_entries,
                    other.acl_entries,
                )

        return diff if diff else None

    @override
    def __str__(self) -> str:
        s = (
            f'Event(event_type={self.event_type.name}, '
            f'process={self.process}, file="{self.file}", '
            f'host_path="{self.host_path}"'
        )

        if self.event_type == EventType.PERMISSION:
            s += f', mode={self.mode}'

        if self.event_type == EventType.OWNERSHIP:
            s += f', owner=(uid={self.owner_uid}, gid={self.owner_gid})'

        if self.event_type == EventType.RENAME:
            s += (
                f', old_file="{self.old_file}"'
                f', old_host_path="{self.old_host_path}"'
            )

        if self.event_type in (EventType.XATTR_SET, EventType.XATTR_REMOVE):
            s += f', xattr_name="{self.xattr_name}"'

        if self.event_type == EventType.ACL:
            s += f', acl_type={self.acl_type}'
            s += f', acl_entries={self.acl_entries}'

        s += ')'

        return s


def selinux_xattr(process: Process, host_path: str = '') -> Event:
    return Event(
        process=process,
        event_type=EventType.XATTR_SET,
        file='',
        host_path=host_path,
        xattr_name='security.selinux',
    )
