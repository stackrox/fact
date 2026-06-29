"""Tests for POSIX ACL change events.

Uses os.setxattr to set ACLs directly via the POSIX ACL xattr wire
format, avoiding a dependency on the setfacl tool.
"""

from __future__ import annotations

import os
import struct

import pytest

from event import (
    ACL_TAG_GROUP_OBJ,
    ACL_TAG_MASK,
    ACL_TAG_OTHER,
    ACL_TAG_USER,
    ACL_TAG_USER_OBJ,
    Event,
    EventType,
    Process,
)
from server import FileActivityService

# POSIX ACL xattr wire format constants
_ACL_VERSION = 2
_ACL_UNDEFINED_ID = 0xFFFFFFFF

# Kernel ACL tag values (from include/uapi/linux/posix_acl.h)
_ACL_USER_OBJ = 0x01
_ACL_USER = 0x02
_ACL_GROUP_OBJ = 0x04
_ACL_GROUP = 0x08
_ACL_MASK = 0x10
_ACL_OTHER = 0x20


def _make_acl_xattr(entries: list[tuple[int, int, int]]) -> bytes:
    """Build a POSIX ACL xattr value from a list of (tag, perm, id) tuples."""
    data = struct.pack('<I', _ACL_VERSION)
    for tag, perm, uid in entries:
        data += struct.pack('<HHI', tag, perm, uid)
    return data


def _kernel_supports_acl_hook() -> bool:
    """Check whether the kernel has the inode_set_acl LSM hook by
    searching for its BTF type in /sys/kernel/btf/vmlinux."""
    needle = b'bpf_lsm_inode_set_acl'
    chunk_size = 64 * 1024
    try:
        with open('/sys/kernel/btf/vmlinux', 'rb') as f:
            # Read in chunks, keeping an overlap to catch matches
            # that span chunk boundaries.
            prev = b''
            while chunk := f.read(chunk_size):
                if needle in prev + chunk:
                    return True
                prev = chunk[-len(needle) :]
        return False
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _kernel_supports_acl_hook(),
    reason='kernel does not support inode_set_acl LSM hook',
)


def test_set_access_acl(
    monitored_dir: str,
    server: FileActivityService,
):
    """Test setting an access ACL on a monitored file."""
    fut = os.path.join(monitored_dir, 'acl_test.txt')
    with open(fut, 'w') as f:
        f.write('test')

    acl = _make_acl_xattr(
        [
            (_ACL_USER_OBJ, 6, _ACL_UNDEFINED_ID),
            (_ACL_USER, 6, 1000),
            (_ACL_GROUP_OBJ, 4, _ACL_UNDEFINED_ID),
            (_ACL_MASK, 6, _ACL_UNDEFINED_ID),
            (_ACL_OTHER, 4, _ACL_UNDEFINED_ID),
        ]
    )
    os.setxattr(fut, 'system.posix_acl_access', acl)

    process = Process.from_proc()
    events = [
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=fut,
            host_path=fut,
        ),
        Event(
            process=process,
            event_type=EventType.ACL,
            file=fut,
            host_path=fut,
            acl_type='access',
            acl_entries=[
                {'tag': ACL_TAG_USER_OBJ, 'perm': 6, 'id': _ACL_UNDEFINED_ID},
                {'tag': ACL_TAG_USER, 'perm': 6, 'id': 1000},
                {'tag': ACL_TAG_GROUP_OBJ, 'perm': 4, 'id': _ACL_UNDEFINED_ID},
                {'tag': ACL_TAG_MASK, 'perm': 6, 'id': _ACL_UNDEFINED_ID},
                {'tag': ACL_TAG_OTHER, 'perm': 4, 'id': _ACL_UNDEFINED_ID},
            ],
        ),
    ]

    server.wait_events(events, skip=())


def test_set_default_acl(
    monitored_dir: str,
    server: FileActivityService,
):
    """Test setting a default ACL on a monitored directory."""
    fut = os.path.join(monitored_dir, 'acl_subdir')
    os.makedirs(fut, exist_ok=True)

    acl = _make_acl_xattr(
        [
            (_ACL_USER_OBJ, 7, _ACL_UNDEFINED_ID),
            (_ACL_GROUP_OBJ, 5, _ACL_UNDEFINED_ID),
            (_ACL_GROUP, 5, 1000),
            (_ACL_MASK, 5, _ACL_UNDEFINED_ID),
            (_ACL_OTHER, 5, _ACL_UNDEFINED_ID),
        ]
    )
    os.setxattr(fut, 'system.posix_acl_default', acl)

    process = Process.from_proc()
    events = [
        Event(
            process=process,
            event_type=EventType.ACL,
            file=fut,
            host_path=fut,
            acl_type='default',
        ),
    ]

    server.wait_events(events, skip=())


def test_remove_acl(
    monitored_dir: str,
    server: FileActivityService,
):
    """Test removing ACLs from a monitored file."""
    fut = os.path.join(monitored_dir, 'acl_remove.txt')
    with open(fut, 'w') as f:
        f.write('test')

    # Set an ACL with an extra user entry
    acl_with_user = _make_acl_xattr(
        [
            (_ACL_USER_OBJ, 6, _ACL_UNDEFINED_ID),
            (_ACL_USER, 6, 1000),
            (_ACL_GROUP_OBJ, 4, _ACL_UNDEFINED_ID),
            (_ACL_MASK, 6, _ACL_UNDEFINED_ID),
            (_ACL_OTHER, 4, _ACL_UNDEFINED_ID),
        ]
    )
    os.setxattr(fut, 'system.posix_acl_access', acl_with_user)

    # Remove extended ACL entries by setting a minimal ACL
    acl_minimal = _make_acl_xattr(
        [
            (_ACL_USER_OBJ, 6, _ACL_UNDEFINED_ID),
            (_ACL_GROUP_OBJ, 4, _ACL_UNDEFINED_ID),
            (_ACL_OTHER, 4, _ACL_UNDEFINED_ID),
        ]
    )
    os.setxattr(fut, 'system.posix_acl_access', acl_minimal)

    process = Process.from_proc()
    events = [
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=fut,
            host_path=fut,
        ),
        Event(
            process=process,
            event_type=EventType.ACL,
            file=fut,
            host_path=fut,
            acl_type='access',
        ),
        Event(
            process=process,
            event_type=EventType.ACL,
            file=fut,
            host_path=fut,
            acl_type='access',
            acl_entries=[
                {'tag': ACL_TAG_USER_OBJ, 'perm': 6, 'id': _ACL_UNDEFINED_ID},
                {'tag': ACL_TAG_GROUP_OBJ, 'perm': 4, 'id': _ACL_UNDEFINED_ID},
                {'tag': ACL_TAG_OTHER, 'perm': 4, 'id': _ACL_UNDEFINED_ID},
            ],
        ),
    ]

    server.wait_events(events, skip=())


def test_multiple_entries(
    monitored_dir: str,
    server: FileActivityService,
):
    """Test setting multiple ACL entries on a single file."""
    fut = os.path.join(monitored_dir, 'acl_multi.txt')
    with open(fut, 'w') as f:
        f.write('test')

    acl = _make_acl_xattr(
        [
            (_ACL_USER_OBJ, 6, _ACL_UNDEFINED_ID),
            (_ACL_USER, 7, 1000),
            (_ACL_USER, 4, 1001),
            (_ACL_GROUP_OBJ, 4, _ACL_UNDEFINED_ID),
            (_ACL_GROUP, 6, 2000),
            (_ACL_MASK, 7, _ACL_UNDEFINED_ID),
            (_ACL_OTHER, 4, _ACL_UNDEFINED_ID),
        ]
    )
    os.setxattr(fut, 'system.posix_acl_access', acl)

    process = Process.from_proc()
    events = [
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=fut,
            host_path=fut,
        ),
        Event(
            process=process,
            event_type=EventType.ACL,
            file=fut,
            host_path=fut,
            acl_type='access',
        ),
    ]

    server.wait_events(events, skip=())


def test_ignored_path(
    test_file: str,
    ignored_dir: str,
    server: FileActivityService,
):
    """Test that ACL changes on ignored paths are not captured."""
    ignored_file = os.path.join(ignored_dir, 'ignored_acl.txt')
    with open(ignored_file, 'w') as f:
        f.write('ignored')

    acl = _make_acl_xattr(
        [
            (_ACL_USER_OBJ, 6, _ACL_UNDEFINED_ID),
            (_ACL_USER, 6, 1000),
            (_ACL_GROUP_OBJ, 4, _ACL_UNDEFINED_ID),
            (_ACL_MASK, 6, _ACL_UNDEFINED_ID),
            (_ACL_OTHER, 4, _ACL_UNDEFINED_ID),
        ]
    )
    os.setxattr(ignored_file, 'system.posix_acl_access', acl)

    # Verify the server is working by doing a chmod on a monitored file
    process = Process.from_proc()
    mode = 0o644
    os.chmod(test_file, mode)

    event = Event(
        process=process,
        event_type=EventType.PERMISSION,
        file=test_file,
        host_path=test_file,
        mode=mode,
    )

    server.wait_events([event])
