from __future__ import annotations

import os

from event import Event, EventType, Process
from server import FileActivityService


def test_setxattr(
    test_file: str,
    server: FileActivityService,
):
    """
    Tests that setting a user xattr on a monitored file generates
    a gRPC xattr event.

    The test_file fixture creates a file before fact starts, so it is
    picked up by the initial scan and its inode is already tracked.

    Args:
        test_file: File monitored on the host.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()

    os.setxattr(test_file, 'user.fact_test', b'test_value')

    server.wait_events(
        [
            Event(
                process=process,
                event_type=EventType.XATTR,
                file='',
                host_path=test_file,
                xattr_name='user.fact_test',
            ),
        ],
        strict=False,
    )


def test_removexattr(
    test_file: str,
    server: FileActivityService,
):
    """
    Tests that removing a user xattr from a monitored file generates
    a gRPC xattr event.

    Args:
        test_file: File monitored on the host.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()

    os.setxattr(test_file, 'user.fact_remove', b'to_remove')
    os.removexattr(test_file, 'user.fact_remove')

    server.wait_events(
        [
            Event(
                process=process,
                event_type=EventType.XATTR,
                file='',
                host_path=test_file,
                xattr_name='user.fact_remove',
            ),
        ],
        strict=False,
    )


def test_setxattr_multiple(
    test_file: str,
    server: FileActivityService,
):
    """
    Tests that setting multiple xattrs on a monitored file generates
    a gRPC event for each.

    Args:
        test_file: File monitored on the host.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()

    os.setxattr(test_file, 'user.attr1', b'value1')
    os.setxattr(test_file, 'user.attr2', b'value2')
    os.setxattr(test_file, 'user.attr3', b'value3')

    server.wait_events(
        [
            Event(
                process=process,
                event_type=EventType.XATTR,
                file='',
                host_path=test_file,
                xattr_name='user.attr1',
            ),
            Event(
                process=process,
                event_type=EventType.XATTR,
                file='',
                host_path=test_file,
                xattr_name='user.attr2',
            ),
            Event(
                process=process,
                event_type=EventType.XATTR,
                file='',
                host_path=test_file,
                xattr_name='user.attr3',
            ),
        ],
        strict=False,
    )


def test_setxattr_ignored(
    test_file: str,
    ignored_dir: str,
    server: FileActivityService,
):
    """
    Tests that xattr changes on unmonitored files are not tracked,
    while xattr changes on monitored files are.

    Args:
        test_file: File monitored on the host.
        ignored_dir: Temporary directory that is not monitored by fact.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()

    ignored_file = os.path.join(ignored_dir, 'ignored.txt')
    with open(ignored_file, 'w') as f:
        f.write('ignored')

    # Set xattr on ignored file - should NOT generate an event
    os.setxattr(ignored_file, 'user.ignored', b'value')

    # Set xattr on monitored file - should generate an event
    os.setxattr(test_file, 'user.monitored', b'value')

    # Only the monitored file's xattr event should arrive
    server.wait_events(
        [
            Event(
                process=process,
                event_type=EventType.XATTR,
                file='',
                host_path=test_file,
                xattr_name='user.monitored',
            ),
        ],
        strict=False,
    )


def test_setxattr_new_file(
    monitored_dir: str,
    server: FileActivityService,
):
    """
    Tests that xattr tracking works for files created while fact is
    running, not just files from the initial scan.

    A new file is created in the monitored directory and its creation
    event is awaited to ensure the inode is tracked before setting
    an xattr.

    Args:
        monitored_dir: Temporary directory path that is monitored.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()

    test_file = os.path.join(monitored_dir, 'xattr_new.txt')
    with open(test_file, 'w') as f:
        f.write('new file')

    server.wait_events(
        [
            Event(
                process=process,
                event_type=EventType.CREATION,
                file=test_file,
                host_path=test_file,
            ),
        ],
    )

    os.setxattr(test_file, 'user.new_file', b'value')

    server.wait_events(
        [
            Event(
                process=process,
                event_type=EventType.XATTR,
                file='',
                host_path=test_file,
                xattr_name='user.new_file',
            ),
        ],
        strict=False,
    )
