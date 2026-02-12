import multiprocessing as mp
import os

import pytest

from conftest import join_path_with_filename, path_to_string
from event import Event, EventType, Process


@pytest.mark.parametrize("filename", [
    'chmod.txt',
    'café.txt',
    'файл.txt',
    '测试.txt',
    '🔒secure.txt',
    b'perm\xff\xfe.txt',
])
def test_chmod(monitored_dir, server, filename):
    """
    Tests changing permissions on a file and verifies the corresponding
    event is captured by the server

    Args:
        monitored_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
        filename: Name of the file to create (includes UTF-8 test cases).
    """
    fut = join_path_with_filename(monitored_dir, filename)

    # Create the file first
    with open(fut, 'w') as f:
        f.write('This is a test')

    mode = 0o666
    os.chmod(fut, mode)

    # Convert fut to string for the Event, replacing invalid UTF-8 with U+FFFD
    fut = path_to_string(fut)

    process = Process.from_proc()
    # We expect both CREATION (from file creation) and PERMISSION (from chmod)
    events = [
        Event(process=process, event_type=EventType.CREATION,
              file=fut, host_path=''),
        Event(process=process, event_type=EventType.PERMISSION,
              file=fut, host_path='', mode=mode),
    ]

    server.wait_events(events)


def test_multiple(monitored_dir, server):
    """
    Tests modifying permissions on multiple files.

    Args:
        monitored_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
    """
    events = []
    process = Process.from_proc()
    mode = 0o646

    for i in range(3):
        fut = os.path.join(monitored_dir, f'{i}.txt')
        with open(fut, 'w') as f:
            f.write('This is a test')
        os.chmod(fut, mode)

        events.extend([
            Event(process=process, event_type=EventType.CREATION,
                  file=fut, host_path=''),
            Event(process=process, event_type=EventType.PERMISSION,
                  file=fut, host_path='', mode=mode),
        ])

    server.wait_events(events)


def test_ignored(test_file, ignored_dir, server):
    """
    Tests that permission events on ignored files are not captured.

    Args:
        test_file: File monitored on the host, mounted to the container.
        ignored_dir: Temporary directory path that is not monitored by fact.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()
    mode = 0o666

    # Ignored file, must not show up in the server
    ignored_file = os.path.join(ignored_dir, 'test.txt')
    with open(ignored_file, 'w') as f:
        f.write('This is to be ignored')
    os.chmod(ignored_file, mode)

    # File Under Test
    os.chmod(test_file, mode)

    e = Event(process=process, event_type=EventType.PERMISSION,
              file=test_file, host_path=test_file, mode=mode)

    server.wait_events([e])


def do_test(fut: str, mode: int, stop_event: mp.Event):
    with open(fut, 'w') as f:
        f.write('This is a test')
    os.chmod(fut, mode)

    # Wait for test to be done
    stop_event.wait()


def test_external_process(monitored_dir, server):
    """
    Tests permission change of a file by an external process and
    verifies that the corresponding event is captured by the server.

    Args:
        monitored_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
    """
    # File Under Test
    fut = os.path.join(monitored_dir, 'test2.txt')
    mode = 0o666
    stop_event = mp.Event()
    proc = mp.Process(target=do_test, args=(fut, mode, stop_event))
    proc.start()
    process = Process.from_proc(proc.pid)

    events = [
        Event(process=process, event_type=EventType.CREATION,
              file=fut, host_path='', mode=mode),
        Event(process=process, event_type=EventType.PERMISSION,
              file=fut, host_path='', mode=mode),
    ]

    try:
        server.wait_events(events)
    finally:
        stop_event.set()
        proc.join(1)


def test_overlay(test_container, server):
    """
    Test permission changes on an overlayfs file (inside a container)

    Args:
        test_container: A container for running commands in.
        server: The server instance to communicate with.
    """
    # File Under Test
    fut = '/container-dir/test.txt'
    mode = '666'

    # Create the exec and an equivalent event that it will trigger
    test_container.exec_run(f'touch {fut}')
    test_container.exec_run(f'chmod {mode} {fut}')

    touch = Process.in_container(
        exe_path='/usr/bin/touch',
        args=f'touch {fut}',
        name='touch',
        container_id=test_container.id[:12],
    )
    chmod = Process.in_container(
        exe_path='/usr/bin/chmod',
        args=f'chmod {mode} {fut}',
        name='chmod',
        container_id=test_container.id[:12],
    )
    events = [
        Event(process=touch, event_type=EventType.CREATION,
              file=fut, host_path=''),
        Event(process=touch, event_type=EventType.OPEN,
              file=fut, host_path=''),
        Event(process=chmod, event_type=EventType.PERMISSION,
              file=fut, host_path='', mode=int(mode, 8)),
    ]

    server.wait_events(events)


def test_mounted_dir(test_container, ignored_dir, server):
    """
    Test permission changes on a file bind mounted into a container

    Args:
        test_container: A container for running commands in.
        ignored_dir: This directory is ignored on the host, and mounted to the container.
        server: The server instance to communicate with.
    """
    # File Under Test
    fut = '/mounted/test.txt'
    mode = '666'

    # Create the exec and an equivalent event that it will trigger
    test_container.exec_run(f'touch {fut}')
    test_container.exec_run(f'chmod {mode} {fut}')

    touch = Process.in_container(
        exe_path='/usr/bin/touch',
        args=f'touch {fut}',
        name='touch',
        container_id=test_container.id[:12],
    )
    chmod = Process.in_container(
        exe_path='/usr/bin/chmod',
        args=f'chmod {mode} {fut}',
        name='chmod',
        container_id=test_container.id[:12],
    )
    events = [
        Event(process=touch, event_type=EventType.CREATION, file=fut,
              host_path=''),
        Event(process=chmod, event_type=EventType.PERMISSION, file=fut,
              host_path='', mode=int(mode, 8)),
    ]

    server.wait_events(events)


def test_unmonitored_mounted_dir(test_container, test_file, server):
    """
    Test permission changes on a file bind mounted to a container and
    monitored on the host.

    Args:
        test_container: A container for running commands in.
        test_file: File monitored on the host, mounted to the container.
        server: The server instance to communicate with.
    """
    # File Under Test
    # The path corresponds to the container, `test_file` is the path on
    # host. Events on this path will trigger via inode tracking.
    fut = '/unmonitored/test.txt'
    mode = '666'

    # Create the exec and an equivalent event that it will trigger
    test_container.exec_run(f'chmod {mode} {fut}')

    process = Process.in_container(
        exe_path='/usr/bin/chmod',
        args=f'chmod {mode} {fut}',
        name='chmod',
        container_id=test_container.id[:12],
    )
    event = Event(process=process, event_type=EventType.PERMISSION,
                  file=fut, host_path=test_file, mode=int(mode, 8))

    server.wait_events([event])
