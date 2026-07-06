"""Tests for POSIX ACL change events.

Uses os.setxattr to set ACLs directly via the POSIX ACL xattr wire
format, avoiding a dependency on the setfacl tool.
"""

from __future__ import annotations

import os
import struct

import pytest

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
from server import EventServer
from utils import btf_has_symbol

# POSIX ACL xattr wire format constants
_ACL_VERSION = 2
_ACL_UNDEFINED_ID = 0xFFFFFFFF

# Kernel ACL tag values (e_tag field in struct posix_acl_entry).
# https://github.com/torvalds/linux/blob/d2c9a99135da931377240942d44f3dea104cedb8/include/uapi/linux/posix_acl.h#L28-L33
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


pytestmark = pytest.mark.skipif(
    not btf_has_symbol('bpf_lsm_inode_set_acl'),
    reason='kernel does not support inode_set_acl LSM hook',
)


def test_set_access_acl(
    test_file: str,
    server: EventServer,
):
    """Test setting an access ACL on a monitored file.

    The test_file fixture creates a file before fact starts, so it is
    picked up by the initial scan and its inode is already tracked.
    """
    process = Process.from_proc()

    acl = _make_acl_xattr(
        [
            (_ACL_USER_OBJ, 6, _ACL_UNDEFINED_ID),
            (_ACL_USER, 6, 1000),
            (_ACL_GROUP_OBJ, 4, _ACL_UNDEFINED_ID),
            (_ACL_MASK, 6, _ACL_UNDEFINED_ID),
            (_ACL_OTHER, 4, _ACL_UNDEFINED_ID),
        ]
    )
    os.setxattr(test_file, 'system.posix_acl_access', acl)

    server.wait_events(
        skip=(),
        events=[
            Event(
                process=process,
                event_type=EventType.ACL,
                file='',
                host_path=test_file,
                acl_type=ACL_TYPE_ACCESS,
                acl_entries=[
                    {
                        'tag': ACL_TAG_USER_OBJ,
                        'perm': 6,
                        'id': _ACL_UNDEFINED_ID,
                    },
                    {'tag': ACL_TAG_USER, 'perm': 6, 'id': 1000},
                    {
                        'tag': ACL_TAG_GROUP_OBJ,
                        'perm': 4,
                        'id': _ACL_UNDEFINED_ID,
                    },
                    {'tag': ACL_TAG_MASK, 'perm': 6, 'id': _ACL_UNDEFINED_ID},
                    {'tag': ACL_TAG_OTHER, 'perm': 4, 'id': _ACL_UNDEFINED_ID},
                ],
            ),
        ],
    )


def test_set_default_acl(
    monitored_dir: str,
    server: EventServer,
):
    """Test setting a default ACL on a monitored directory.

    ACL changes are only detected on inode-tracked paths.
    """
    process = Process.from_proc()

    acl = _make_acl_xattr(
        [
            (_ACL_USER_OBJ, 7, _ACL_UNDEFINED_ID),
            (_ACL_GROUP_OBJ, 5, _ACL_UNDEFINED_ID),
            (_ACL_GROUP, 5, 1000),
            (_ACL_MASK, 5, _ACL_UNDEFINED_ID),
            (_ACL_OTHER, 5, _ACL_UNDEFINED_ID),
        ]
    )
    os.setxattr(monitored_dir, 'system.posix_acl_default', acl)

    server.wait_events(
        skip=(),
        events=[
            Event(
                process=process,
                event_type=EventType.ACL,
                file='',
                host_path=monitored_dir,
                acl_type=ACL_TYPE_DEFAULT,
            ),
        ],
    )


def test_remove_acl(
    test_file: str,
    server: EventServer,
):
    """Test setting and then removing ACLs from a monitored file."""
    process = Process.from_proc()

    acl_with_user = _make_acl_xattr(
        [
            (_ACL_USER_OBJ, 6, _ACL_UNDEFINED_ID),
            (_ACL_USER, 6, 1000),
            (_ACL_GROUP_OBJ, 4, _ACL_UNDEFINED_ID),
            (_ACL_MASK, 6, _ACL_UNDEFINED_ID),
            (_ACL_OTHER, 4, _ACL_UNDEFINED_ID),
        ]
    )
    os.setxattr(test_file, 'system.posix_acl_access', acl_with_user)

    acl_minimal = _make_acl_xattr(
        [
            (_ACL_USER_OBJ, 6, _ACL_UNDEFINED_ID),
            (_ACL_GROUP_OBJ, 4, _ACL_UNDEFINED_ID),
            (_ACL_OTHER, 4, _ACL_UNDEFINED_ID),
        ]
    )
    os.setxattr(test_file, 'system.posix_acl_access', acl_minimal)

    server.wait_events(
        skip=(),
        events=[
            Event(
                process=process,
                event_type=EventType.ACL,
                file='',
                host_path=test_file,
                acl_type=ACL_TYPE_ACCESS,
            ),
            Event(
                process=process,
                event_type=EventType.ACL,
                file='',
                host_path=test_file,
                acl_type=ACL_TYPE_ACCESS,
                acl_entries=[
                    {
                        'tag': ACL_TAG_USER_OBJ,
                        'perm': 6,
                        'id': _ACL_UNDEFINED_ID,
                    },
                    {
                        'tag': ACL_TAG_GROUP_OBJ,
                        'perm': 4,
                        'id': _ACL_UNDEFINED_ID,
                    },
                    {'tag': ACL_TAG_OTHER, 'perm': 4, 'id': _ACL_UNDEFINED_ID},
                ],
            ),
        ],
    )


def test_multiple_entries(
    test_file: str,
    server: EventServer,
):
    """Test setting multiple ACL entries on a single file."""
    process = Process.from_proc()

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
    os.setxattr(test_file, 'system.posix_acl_access', acl)

    server.wait_events(
        skip=(),
        events=[
            Event(
                process=process,
                event_type=EventType.ACL,
                file='',
                host_path=test_file,
                acl_type=ACL_TYPE_ACCESS,
                acl_entries=[
                    {
                        'tag': ACL_TAG_USER_OBJ,
                        'perm': 6,
                        'id': _ACL_UNDEFINED_ID,
                    },
                    {'tag': ACL_TAG_USER, 'perm': 7, 'id': 1000},
                    {'tag': ACL_TAG_USER, 'perm': 4, 'id': 1001},
                    {
                        'tag': ACL_TAG_GROUP_OBJ,
                        'perm': 4,
                        'id': _ACL_UNDEFINED_ID,
                    },
                    {'tag': ACL_TAG_GROUP, 'perm': 6, 'id': 2000},
                    {'tag': ACL_TAG_MASK, 'perm': 7, 'id': _ACL_UNDEFINED_ID},
                    {'tag': ACL_TAG_OTHER, 'perm': 4, 'id': _ACL_UNDEFINED_ID},
                ],
            ),
        ],
    )


def test_ignored_path(
    test_file: str,
    ignored_dir: str,
    server: EventServer,
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

    # Verify the server is working by setting an ACL on a monitored file.
    # We use an ACL event (not chmod) so that this test cannot silently
    # pass if ACL events specifically are broken or filtered.
    process = Process.from_proc()
    monitored_acl = _make_acl_xattr(
        [
            (_ACL_USER_OBJ, 6, _ACL_UNDEFINED_ID),
            (_ACL_GROUP_OBJ, 4, _ACL_UNDEFINED_ID),
            (_ACL_OTHER, 4, _ACL_UNDEFINED_ID),
        ]
    )
    os.setxattr(test_file, 'system.posix_acl_access', monitored_acl)

    event = Event(
        process=process,
        event_type=EventType.ACL,
        file='',
        host_path=test_file,
        acl_type=ACL_TYPE_ACCESS,
        acl_entries=[
            {
                'tag': ACL_TAG_USER_OBJ,
                'perm': 6,
                'id': _ACL_UNDEFINED_ID,
            },
            {
                'tag': ACL_TAG_GROUP_OBJ,
                'perm': 4,
                'id': _ACL_UNDEFINED_ID,
            },
            {'tag': ACL_TAG_OTHER, 'perm': 4, 'id': _ACL_UNDEFINED_ID},
        ],
    )

    server.wait_events([event], skip=())
