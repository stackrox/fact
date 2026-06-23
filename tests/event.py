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
    RENAME = 6
    XATTR_SET = 7
    XATTR_REMOVE = 8
        acl_type: str | None = None,
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
    def acl_type(self) -> str | None:
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
        actual: str,
    ):
        """
        Compare paths with regex pattern support.
        """
        if isinstance(expected, Pattern):
            if not expected.match(actual):
                diff[name] = {'expected': f'{expected}', 'actual': actual}
        elif expected != actual:
            diff[name] = {'expected': expected, 'actual': actual}

    def diff(self, other: FileActivity) -> dict | None:
        """
        Compare this Event with a FileActivity protobuf message.

        Args:
            other: FileActivity protobuf message to compare against

        Returns:
            None if identical, dict of differences if not matching
        """
        diff = {}

        # Check process differences first
        process_diff = self.process.diff(other.process)
        if process_diff is not None:
            diff['process'] = process_diff

        # Check event type
        event_type_expected = self.event_type.name.lower()
        event_type_actual = other.WhichOneof('file')

        Event._diff_field(
            diff,
            'event_type',
            event_type_expected,
            event_type_actual,
        )
        if diff:
            return diff

        # Get the appropriate event field based on type
        event_field = getattr(other, event_type_expected)

        # Rename handling is a bit different to the rest, since it has
        # new and old paths.
        if self.event_type == EventType.RENAME:
            Event._diff_path(diff, 'new_file', self.file, event_field.new.path)
            Event._diff_path(
                diff,
                'new_host_path',
                self.host_path,
                event_field.new.host_path,
            )
            Event._diff_path(
                diff,
                'old_file',
                self.old_file,
                event_field.old.path,
            )
            Event._diff_path(
                diff,
                'old_host_path',
                self.old_host_path,
                event_field.old.host_path,
            )
            return diff if diff else None

        # Compare file and host_path (common to all event types)
        # All event types have .activity.path and .activity.host_path
        # accessed differently
        Event._diff_path(diff, 'file', self.file, event_field.activity.path)
        Event._diff_path(
            diff,
            'host_path',
            self.host_path,
            event_field.activity.host_path,
        )

        if self.event_type == EventType.PERMISSION:
            Event._diff_field(diff, 'mode', self.mode, event_field.mode)
        elif self.event_type == EventType.OWNERSHIP:
            Event._diff_field(
                diff,
                'owner_uid',
                self.owner_uid,
                event_field.uid,
            )
            Event._diff_field(
                diff,
                'owner_gid',
                self.owner_gid,
                event_field.gid,
            )
        elif self.event_type in (EventType.XATTR_SET, EventType.XATTR_REMOVE):
            Event._diff_field(
                diff,
                'xattr_name',
                self.xattr_name,
                event_field.xattr_name,
            )
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
