from __future__ import annotations

import multiprocessing as mp
import os
from multiprocessing.synchronize import Event as MpEvent

import docker.models.containers
import pytest

from event import Event, EventType, Process
from server import EventServer
from utils import join_path_with_filename, path_to_string


@pytest.mark.parametrize(
    'filename',
    [
        'remove.txt',
        'café.txt',
        'файл.txt',
        '测试.txt',
        '🗑️delete.txt',
        b'rm\xff\xfe.txt',
    ],
)
def test_remove(
    monitored_dir: str,
    server: EventServer,
    filename: str | bytes,
):
    """
    Tests the removal of a file and verifies the corresponding event is
    captured by the server.

    Args:
        monitored_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
        filename: Name of the file to create and remove
            (includes UTF-8 test cases).
    """

    # File under test
    fut = join_path_with_filename(monitored_dir, filename)

    # Create the file first
    with open(fut, 'w') as f:
        f.write('This is a test')

    # Remove the file
    os.remove(fut)

    # Convert test_file to string for the Event,
    # replacing invalid UTF-8 with U+FFFD
    fut = path_to_string(fut)

    process = Process.from_proc()
    # We expect both CREATION (from file creation) and UNLINK (from removal)
    events = [
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=fut,
            host_path=fut,
        ),
        Event(
            process=process,
            event_type=EventType.UNLINK,
            file=fut,
            host_path=fut,
        ),
    ]

    server.wait_events(events)


def test_multiple(monitored_dir: str, server: EventServer):
    """
    Tests the removal of multiple files and verifies the corresponding
    events are captured by the server.

    Args:
        monitored_dir: Temporary directory path for monitoring the test file.
        server: The server instance to communicate with.
    """
    events = []
    process = Process.from_proc()

    # File Under Test
    for i in range(3):
        fut = os.path.join(monitored_dir, f'{i}.txt')
        with open(fut, 'w') as f:
            f.write('This is a test')
        os.remove(fut)

        events.extend(
            [
                Event(
                    process=process,
                    event_type=EventType.CREATION,
                    file=fut,
                    host_path=fut,
                ),
                Event(
                    process=process,
                    event_type=EventType.UNLINK,
                    file=fut,
                    host_path=fut,
                ),
            ],
        )

    server.wait_events(events)


def test_ignored(test_file: str, ignored_dir: str, server: EventServer):
    """
    Tests that unlink events on ignored files are not captured by the
    server.

    Args:
        monitored_dir: Temporary directory path for creating the test file.
        ignored_dir: Temporary directory path that is not monitored by fact.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()

    # Ignored file, must not show up in the server
    ignored_file = os.path.join(ignored_dir, 'test.txt')
    with open(ignored_file, 'w') as f:
        f.write('This is to be ignored')
    os.remove(ignored_file)

    # File Under Test
    os.remove(test_file)

    e = Event(
        process=process,
        event_type=EventType.UNLINK,
        file=test_file,
        host_path=test_file,
    )

    server.wait_events([e])


def do_test(fut: str, stop_event: MpEvent):
    with open(fut, 'w') as f:
        f.write('This is a test')
    os.remove(fut)

    # Wait for test to be done
    stop_event.wait()


def test_external_process(monitored_dir: str, server: EventServer):
    """
    Tests the removal of a file by an external process and verifies that
    the corresponding event is captured by the server.

    Args:
        monitored_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
    """
    # File Under Test
    fut = os.path.join(monitored_dir, 'test2.txt')
    stop_event = mp.Event()
    proc = mp.Process(target=do_test, args=(fut, stop_event))
    proc.start()
    process = Process.from_proc(proc.pid)

    events = [
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=fut,
            host_path=fut,
        ),
        Event(
            process=process,
            event_type=EventType.UNLINK,
            file=fut,
            host_path=fut,
        ),
    ]

    try:
        server.wait_events(events)
    finally:
        stop_event.set()
        proc.join(1)


def test_overlay(
    test_container: docker.models.containers.Container,
    server: EventServer,
):
    assert test_container.id is not None
    # File Under Test
    fut = '/container-dir/test.txt'

    # Create the exec and an equivalent event that it will trigger
    test_container.exec_run(f'touch {fut}')
    test_container.exec_run(f'rm {fut}')

    touch = Process.in_container(
        exe_path='/usr/bin/touch',
        args=f'touch {fut}',
        name='touch',
        container_id=test_container.id[:12],
    )
    rm = Process.in_container(
        exe_path='/usr/bin/rm',
        args=f'rm {fut}',
        name='rm',
        container_id=test_container.id[:12],
    )
    events = [
        Event(
            process=touch,
            event_type=EventType.CREATION,
            file=fut,
            host_path='',
        ),
        Event(
            process=rm,
            event_type=EventType.UNLINK,
            file=fut,
            host_path='',
        ),
    ]

    server.wait_events(events)


def test_mounted_dir(
    test_container: docker.models.containers.Container,
    ignored_dir: str,
    server: EventServer,
):
    assert test_container.id is not None
    # File Under Test
    fut = '/mounted/test.txt'

    # Create the exec and an equivalent event that it will trigger
    test_container.exec_run(f'touch {fut}')
    test_container.exec_run(f'rm {fut}')

    touch = Process.in_container(
        exe_path='/usr/bin/touch',
        args=f'touch {fut}',
        name='touch',
        container_id=test_container.id[:12],
    )
    rm = Process.in_container(
        exe_path='/usr/bin/rm',
        args=f'rm {fut}',
        name='rm',
        container_id=test_container.id[:12],
    )
    # ignored_dir is not monitored, so host_path should be blank
    events = [
        Event(
            process=touch,
            event_type=EventType.CREATION,
            file=fut,
            host_path='',
        ),
        Event(
            process=rm,
            event_type=EventType.UNLINK,
            file=fut,
            host_path='',
        ),
    ]

    server.wait_events(events)


def test_unmonitored_mounted_dir(
    test_container: docker.models.containers.Container,
    test_file: str,
    server: EventServer,
):
    assert test_container.id is not None
    # File Under Test
    fut = '/unmonitored/test.txt'

    # Create the exec and an equivalent event that it will trigger
    test_container.exec_run(f'rm {fut}')

    process = Process.in_container(
        exe_path='/usr/bin/rm',
        args=f'rm {fut}',
        name='rm',
        container_id=test_container.id[:12],
    )
    event = Event(
        process=process,
        event_type=EventType.UNLINK,
        file=fut,
        host_path=test_file,
    )

    server.wait_events([event])


def test_unlink_last_monitored_hardlink(
    monitored_dir: str, ignored_dir: str, server: EventServer
):
    """
    Tests that unlinking the last monitored hardlink removes the inode
    from tracking, even when ignored hardlinks still exist.

    Args:
        monitored_dir: Temporary directory path for creating test files.
        ignored_dir: Temporary directory path that is not monitored by fact.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()

    # Create file in monitored directory
    monitored = os.path.join(monitored_dir, 'file.txt')
    with open(monitored, 'w') as f:
        f.write('test content')

    # Create hardlink in ignored directory
    ignored_link = os.path.join(ignored_dir, 'link.txt')
    os.link(monitored, ignored_link)

    # Unlink the monitored path
    os.unlink(monitored)

    # Access via ignored link should not generate event
    with open(ignored_link) as f:
        f.read()

    sentinel = os.path.join(monitored_dir, 'sentinel.txt')
    with open(sentinel, 'w') as f:
        f.write('sentinel')

    # Creation for original, creation for ignored link (inode tracked),
    # then unlink
    events = [
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=monitored,
            host_path=monitored,
        ),
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=ignored_link,
            host_path=monitored,
        ),
        Event(
            process=process,
            event_type=EventType.UNLINK,
            file=monitored,
            host_path=monitored,
        ),
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=sentinel,
            host_path=sentinel,
        ),
    ]

    server.wait_events(events)


def test_unlink_one_of_multiple_monitored_hardlinks(
    monitored_dir: str, ignored_dir: str, server: EventServer
):
    """
    Tests that unlinking one monitored hardlink keeps the inode tracked
    when other monitored and ignored hardlinks remain.

    Args:
        monitored_dir: Temporary directory path for creating test files.
        ignored_dir: Temporary directory path that is not monitored by fact.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()

    # Create file in monitored directory
    monitored1 = os.path.join(monitored_dir, 'file1.txt')
    with open(monitored1, 'w') as f:
        f.write('test content')

    # Create another monitored hardlink and an ignored hardlink
    monitored2 = os.path.join(monitored_dir, 'file2.txt')
    ignored_link = os.path.join(ignored_dir, 'link.txt')
    os.link(monitored1, monitored2)
    os.link(monitored1, ignored_link)

    # Unlink one monitored path
    os.unlink(monitored1)

    # Inode should still be tracked - access via other monitored path
    with open(ignored_link, 'w') as f:
        f.write('modified content')

    events = [
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=monitored1,
            host_path=monitored1,
        ),
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=monitored2,
            host_path=monitored1,
        ),
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=ignored_link,
            host_path=monitored1,
        ),
        Event(
            process=process,
            event_type=EventType.UNLINK,
            file=monitored1,
            host_path=monitored1,
        ),
        Event(
            process=process,
            event_type=EventType.OPEN,
            file=ignored_link,
            host_path=monitored1,
        ),
    ]

    server.wait_events(events)


def test_unlink_original_access_via_hardlink(
    monitored_dir: str, server: EventServer
):
    """
    Tests that unlinking the original file (the path in inode_map)
    keeps the inode tracked and accessible via the remaining hardlink.

    Args:
        monitored_dir: Temporary directory path for creating test files.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()

    # Create original file
    original = os.path.join(monitored_dir, 'original.txt')
    with open(original, 'w') as f:
        f.write('test content')

    # Create hardlink
    hardlink = os.path.join(monitored_dir, 'hardlink.txt')
    os.link(original, hardlink)

    # Unlink the original (the path stored in inode_map)
    os.unlink(original)

    # Access through remaining hardlink
    with open(hardlink, 'w') as f:
        f.write('still tracked')

    events = [
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=original,
            host_path=original,
        ),
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=hardlink,
            host_path=original,
        ),
        Event(
            process=process,
            event_type=EventType.UNLINK,
            file=original,
            host_path=original,
        ),
        Event(
            process=process,
            event_type=EventType.OPEN,
            file=hardlink,
            host_path=original,
        ),
    ]

    server.wait_events(events)


def test_unlink_ignored_hardlink_keeps_monitored(
    monitored_dir: str, ignored_dir: str, server: EventServer
):
    """
    Tests that unlinking an ignored hardlink does not remove the inode
    from tracking. The monitored file should still generate events.

    Args:
        monitored_dir: Temporary directory path for creating test files.
        ignored_dir: Temporary directory path that is not monitored by fact.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()

    # Create file in monitored directory
    monitored = os.path.join(monitored_dir, 'file.txt')
    with open(monitored, 'w') as f:
        f.write('test content')

    # Create hardlink in ignored directory
    ignored_link = os.path.join(ignored_dir, 'link.txt')
    os.link(monitored, ignored_link)

    # Unlink the ignored hardlink
    os.unlink(ignored_link)

    # Monitored file should still be tracked
    with open(monitored, 'w') as f:
        f.write('still tracked')

    events = [
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=monitored,
            host_path=monitored,
        ),
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=ignored_link,
            host_path=monitored,
        ),
        Event(
            process=process,
            event_type=EventType.UNLINK,
            file=ignored_link,
            host_path=monitored,
        ),
        Event(
            process=process,
            event_type=EventType.OPEN,
            file=monitored,
            host_path=monitored,
        ),
    ]

    server.wait_events(events)


def test_sequential_unlink_all_hardlinks(
    monitored_dir: str, server: EventServer
):
    """
    Tests sequential unlinking of hardlinks with access checks between
    each, verifying the inode is tracked until the last link is removed.

    Args:
        monitored_dir: Temporary directory path for creating test files.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()

    # Create original + 2 hardlinks (refcount=3)
    original = os.path.join(monitored_dir, 'original.txt')
    with open(original, 'w') as f:
        f.write('test content')
    link1 = os.path.join(monitored_dir, 'link1.txt')
    link2 = os.path.join(monitored_dir, 'link2.txt')
    os.link(original, link1)
    os.link(original, link2)

    # Unlink link1 (refcount 3->2), verify access via link2
    os.unlink(link1)
    with open(link2, 'w') as f:
        f.write('after first unlink')

    # Unlink original (refcount 2->1), verify access via link2
    os.unlink(original)
    with open(link2, 'w') as f:
        f.write('after second unlink')

    # Unlink link2 (refcount 1->0), inode removed from tracking
    os.unlink(link2)

    # Sentinel to drain the queue
    sentinel = os.path.join(monitored_dir, 'sentinel.txt')
    with open(sentinel, 'w') as f:
        f.write('sentinel')

    events = [
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=original,
            host_path=original,
        ),
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=link1,
            host_path=original,
        ),
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=link2,
            host_path=original,
        ),
        # First unlink + access
        Event(
            process=process,
            event_type=EventType.UNLINK,
            file=link1,
            host_path=original,
        ),
        Event(
            process=process,
            event_type=EventType.OPEN,
            file=link2,
            host_path=original,
        ),
        # Second unlink + access
        Event(
            process=process,
            event_type=EventType.UNLINK,
            file=original,
            host_path=original,
        ),
        Event(
            process=process,
            event_type=EventType.OPEN,
            file=link2,
            host_path=original,
        ),
        # Final unlink
        Event(
            process=process,
            event_type=EventType.UNLINK,
            file=link2,
            host_path=original,
        ),
        # Sentinel confirms no spurious events
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=sentinel,
            host_path=sentinel,
        ),
    ]

    server.wait_events(events)
