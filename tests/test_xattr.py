from __future__ import annotations

import os

import pytest

from event import Event, EventType, Process
from server import FileActivityService
from utils import join_path_with_filename, path_to_string


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
        skip_xattr=False,
        events=[
            Event(
                process=process,
                event_type=EventType.XATTR_SET,
                file='',
                host_path=test_file,
                xattr_name='user.fact_test',
            ),
        ],
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
        skip_xattr=False,
        events=[
            Event(
                process=process,
                event_type=EventType.XATTR_SET,
                file='',
                host_path=test_file,
                xattr_name='user.fact_remove',
            ),
            Event(
                process=process,
                event_type=EventType.XATTR_REMOVE,
                file='',
                host_path=test_file,
                xattr_name='user.fact_remove',
            ),
        ],
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
    os.removexattr(test_file, 'user.attr1')
    os.removexattr(test_file, 'user.attr2')
    os.removexattr(test_file, 'user.attr3')

    server.wait_events(
        skip_xattr=False,
        events=[
            Event(
                process=process,
                event_type=EventType.XATTR_SET,
                file='',
                host_path=test_file,
                xattr_name='user.attr1',
            ),
            Event(
                process=process,
                event_type=EventType.XATTR_SET,
                file='',
                host_path=test_file,
                xattr_name='user.attr2',
            ),
            Event(
                process=process,
                event_type=EventType.XATTR_SET,
                file='',
                host_path=test_file,
                xattr_name='user.attr3',
            ),
            Event(
                process=process,
                event_type=EventType.XATTR_REMOVE,
                file='',
                host_path=test_file,
                xattr_name='user.attr1',
            ),
            Event(
                process=process,
                event_type=EventType.XATTR_REMOVE,
                file='',
                host_path=test_file,
                xattr_name='user.attr2',
            ),
            Event(
                process=process,
                event_type=EventType.XATTR_REMOVE,
                file='',
                host_path=test_file,
                xattr_name='user.attr3',
            ),
        ],
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
        skip_xattr=False,
        events=[
            Event(
                process=process,
                event_type=EventType.XATTR_SET,
                file='',
                host_path=test_file,
                xattr_name='user.monitored',
            ),
        ],
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
        skip_xattr=False,
        events=[
            Event(
                process=process,
                event_type=EventType.XATTR_SET,
                file='',
                host_path=test_file,
                xattr_name='user.new_file',
            ),
        ],
    )


@pytest.mark.parametrize(
    'filename',
    [
        pytest.param('xattr.txt', id='ASCII'),
        pytest.param('café.txt', id='French'),
        pytest.param('файл.txt', id='Cyrillic'),
        pytest.param('测试.txt', id='Chinese'),
        pytest.param('🔒secure.txt', id='Emoji'),
        pytest.param(b'xattr\xff\xfe.txt', id='InvalidUTF8'),
    ],
)
def test_setxattr_utf8_filenames(
    monitored_dir: str,
    server: FileActivityService,
    filename: str | bytes,
):
    """
    Tests that xattr events are correctly tracked on files with
    various UTF-8 and non-UTF-8 filenames.

    Args:
        monitored_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
        filename: Name of the file to create (includes UTF-8 test cases).
    """
    fut = join_path_with_filename(monitored_dir, filename)

    with open(fut, 'w') as f:
        f.write('test')

    # gRPC events use lossy UTF-8 conversion, but os.setxattr
    # needs the original path to find the file on disk.
    fut_str = path_to_string(fut)

    process = Process.from_proc()

    server.wait_events(
        [
            Event(
                process=process,
                event_type=EventType.CREATION,
                file=fut_str,
                host_path=fut_str,
            ),
        ],
    )

    os.setxattr(fut, 'user.utf8_test', b'value')

    server.wait_events(
        skip_xattr=False,
        events=[
            Event(
                process=process,
                event_type=EventType.XATTR_SET,
                file='',
                host_path=fut_str,
                xattr_name='user.utf8_test',
            ),
        ],
    )
