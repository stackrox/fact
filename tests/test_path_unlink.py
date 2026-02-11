import multiprocessing as mp
import os

import docker
import pytest

from conftest import join_path_with_filename, path_to_string
from event import Event, EventType, Process


@pytest.mark.parametrize("filename", [
    'remove.txt',
    'café.txt',
    'файл.txt',
    '测试.txt',
    '🗑️delete.txt',
    b'rm\xff\xfe.txt',
])
def test_remove(fact, monitored_dir, server, filename):
    """
    Tests the removal of a file and verifies the corresponding event is
    captured by the server.

    Args:
        fact: Fixture for file activity (only required to be running).
        monitored_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
        filename: Name of the file to create and remove (includes UTF-8 test cases).
    """
    test_file = join_path_with_filename(monitored_dir, filename)

    # Create the file first
    with open(test_file, 'w') as f:
        f.write('This is a test')

    # Remove the file
    os.remove(test_file)

    # Convert test_file to string for the Event, replacing invalid UTF-8 with U+FFFD
    test_file = path_to_string(test_file)

    process = Process.from_proc()
    # We expect both CREATION (from file creation) and UNLINK (from removal)
    events = [
        Event(process=process, event_type=EventType.CREATION,
              file=test_file_str, host_path=''),
        Event(process=process, event_type=EventType.UNLINK,
              file=test_file_str, host_path=''),
    ]

    server.wait_events(events)


def test_multiple(fact, monitored_dir, server):
    """
    Tests the removal of multiple files and verifies the corresponding
    events are captured by the server.

    Args:
        fact: Fixture for file activity (only required to be running).
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

        events.extend([
            Event(process=process, event_type=EventType.CREATION,
                  file=fut, host_path=''),
            Event(process=process, event_type=EventType.UNLINK,
                  file=fut, host_path=''),
        ])

    server.wait_events(events)


def test_ignored(fact, test_file, ignored_dir, server):
    """
    Tests that unlink events on ignored files are not captured by the
    server.

    Args:
        fact: Fixture for file activity (only required to be running).
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

    ignored_event = Event(process=process, event_type=EventType.UNLINK,
                          file=ignored_file, host_path='')
    print(f'Ignoring: {ignored_event}')

    # File Under Test
    os.remove(test_file)

    e = Event(process=process, event_type=EventType.UNLINK,
              file=test_file, host_path=test_file)
    print(f'Waiting for event: {e}')

    server.wait_events([e], ignored=[ignored_event])


def do_test(fut: str, stop_event: mp.Event):
    with open(fut, 'w') as f:
        f.write('This is a test')
    os.remove(fut)

    # Wait for test to be done
    stop_event.wait()


def test_external_process(fact, monitored_dir, server):
    """
    Tests the removal of a file by an external process and verifies that
    the corresponding event is captured by the server.

    Args:
        fact: Fixture for file activity (only required to be running).
        monitored_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
    """
    # File Under Test
    fut = os.path.join(monitored_dir, 'test2.txt')
    stop_event = mp.Event()
    proc = mp.Process(target=do_test, args=(fut, stop_event))
    proc.start()
    process = Process.from_proc(proc.pid)

    removal = Event(process=process, event_type=EventType.UNLINK,
                    file=fut, host_path='')
    print(f'Waiting for event: {removal}')

    try:
        server.wait_events([removal])
    finally:
        stop_event.set()
        proc.join(1)


def test_overlay(fact, test_container, server):
    # File Under Test
    fut = '/container-dir/test.txt'

    # Create the exec and an equivalent event that it will trigger
    test_container.exec_run(f'touch {fut}')
    test_container.exec_run(f'rm {fut}')

    loginuid = pow(2, 32)-1
    touch = Process(pid=None,
                    uid=0,
                    gid=0,
                    exe_path='/usr/bin/touch',
                    args=f'touch {fut}',
                    name='touch',
                    container_id=test_container.id[:12],
                    loginuid=loginuid)
    rm = Process(pid=None,
                 uid=0,
                 gid=0,
                 exe_path='/usr/bin/rm',
                 args=f'rm {fut}',
                 name='rm',
                 container_id=test_container.id[:12],
                 loginuid=loginuid)
    events = [
        Event(process=touch, event_type=EventType.CREATION,
              file=fut, host_path=''),
        Event(process=touch, event_type=EventType.OPEN,
              file=fut, host_path=''),
        Event(process=rm, event_type=EventType.UNLINK,
              file=fut, host_path=''),
    ]

    for e in events:
        print(f'Waiting for event: {e}')

    server.wait_events(events)


def test_mounted_dir(fact, test_container, ignored_dir, server):
    # File Under Test
    fut = '/mounted/test.txt'

    # Create the exec and an equivalent event that it will trigger
    test_container.exec_run(f'touch {fut}')
    test_container.exec_run(f'rm {fut}')

    loginuid = pow(2, 32)-1
    touch = Process(pid=None,
                    uid=0,
                    gid=0,
                    exe_path='/usr/bin/touch',
                    args=f'touch {fut}',
                    name='touch',
                    container_id=test_container.id[:12],
                    loginuid=loginuid)
    rm = Process(pid=None,
                 uid=0,
                 gid=0,
                 exe_path='/usr/bin/rm',
                 args=f'rm {fut}',
                 name='rm',
                 container_id=test_container.id[:12],
                 loginuid=loginuid)
    events = [
        Event(process=touch, event_type=EventType.CREATION, file=fut,
              host_path=''),
        Event(process=rm, event_type=EventType.UNLINK, file=fut,
              host_path=''),
    ]

    for e in events:
        print(f'Waiting for event: {e}')

    server.wait_events(events)


def test_unmonitored_mounted_dir(fact, test_container, test_file, server):
    # File Under Test
    fut = '/unmonitored/test.txt'

    # Create the exec and an equivalent event that it will trigger
    test_container.exec_run(f'rm {fut}')

    process = Process(pid=None,
                      uid=0,
                      gid=0,
                      exe_path='/usr/bin/rm',
                      args=f'rm {fut}',
                      name='rm',
                      container_id=test_container.id[:12],
                      loginuid=pow(2, 32)-1)
    event = Event(process=process, event_type=EventType.UNLINK,
                  file=fut, host_path=test_file)
    print(f'Waiting for event: {event}')

    server.wait_events([event])
