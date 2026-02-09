import multiprocessing as mp
import os

import docker
import pytest

from conftest import join_path_with_filename, path_to_string
from event import Event, EventType, Process


@pytest.mark.parametrize("filename", [
    pytest.param('create.txt', id='ascii'),
    pytest.param('café.txt', id='spanish'),
    pytest.param('файл.txt', id='cyrilic'),
    pytest.param('测试.txt', id='chinese'),
    pytest.param('🚀rocket.txt', id='emoji'),
    pytest.param(b'test\xff\xfe.txt', id='invalid'),
])
def test_open(fact, monitored_dir, server, filename):
    """
    Tests the opening of a file and verifies that the corresponding
    event is captured by the server.

    Args:
        fact: Fixture for file activity (only required to be running).
        monitored_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
        filename: Name of the file to create (includes UTF-8 test cases).
    """
    # File Under Test
    fut = join_path_with_filename(monitored_dir, filename)

    with open(fut, 'w') as f:
        f.write('This is a test')

    # Convert fut to string for the Event, replacing invalid UTF-8 with U+FFFD
    fut_str = path_to_string(fut)

    e = Event(process=Process.from_proc(), event_type=EventType.CREATION,
              file=fut_str, host_path='')
    print(f'Waiting for event: {e}')

    server.wait_events([e])


def test_multiple(fact, monitored_dir, server):
    """
    Tests the opening of multiple files and verifies that the
    corresponding events are captured by the server.

    Args:
        fact: Fixture for file activity (only required to be running).
        monitored_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
        filenames: List of filenames to create (includes UTF-8 test cases).
    """
    events = []
    process = Process.from_proc()
    # File Under Test
    for i in range(3):
        fut = os.path.join(monitored_dir, f'{i}.txt')
        with open(fut, 'w') as f:
            f.write('This is a test')

        e = Event(process=process, event_type=EventType.CREATION,
                  file=fut, host_path='')
        print(f'Waiting for event: {e}')
        events.append(e)

    server.wait_events(events)


def test_multiple_access(fact, test_file, server):
    """
    Tests multiple opening of a file and verifies that the
    corresponding events are captured by the server.

    Args:
        fact: Fixture for file activity (only required to be running).
        monitored_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
    """
    events = []
    for i in range(3):
        with open(test_file, 'a+') as f:
            f.write('This is a test')

        e = Event(process=Process.from_proc(), file=test_file,
                  host_path=test_file, event_type=EventType.OPEN)
        print(f'Waiting for event: {e}')
        events.append(e)

    server.wait_events(events)


def test_ignored(fact, test_file, ignored_dir, server):
    """
    Tests that open events on ignored files are not captured by the
    server.

    Args:
        fact: Fixture for file activity (only required to be running).
        test_file: Temporary file for testing.
        ignored_dir: Temporary directory path that is not monitored by fact.
        server: The server instance to communicate with.
    """
    p = Process.from_proc()

    # Ignored file, must not show up in the server
    ignored_file = os.path.join(ignored_dir, 'test.txt')
    with open(ignored_file, 'w') as f:
        f.write('This is to be ignored')

    ignored_event = Event(process=p, event_type=EventType.CREATION,
                          file=ignored_file, host_path='')
    print(f'Ignoring: {ignored_event}')

    # File Under Test
    with open(test_file, 'w') as f:
        f.write('This is a test')

    e = Event(process=p, event_type=EventType.OPEN,
              file=test_file, host_path=test_file)
    print(f'Waiting for event: {e}')

    server.wait_events([e], ignored=[ignored_event])


def do_test(fut: str, stop_event: mp.Event):
    with open(fut, 'w') as f:
        f.write('This is a test')
    with open(fut, 'a') as f:
        f.write('This is also a test')

    # Wait for test to be done
    stop_event.wait()


def test_external_process(fact, monitored_dir, server):
    """
    Tests the opening of a file by an external process and verifies that
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
    p = Process.from_proc(proc.pid)

    creation = Event(process=p, event_type=EventType.CREATION,
                     file=fut, host_path='')
    print(f'Waiting for event: {creation}')
    write_access = Event(
        process=p, event_type=EventType.OPEN, file=fut, host_path='')
    print(f'Waiting for event: {write_access}')

    try:
        server.wait_events([creation, write_access])
    finally:
        stop_event.set()
        proc.join(1)


def test_overlay(fact, test_container, server):
    # File Under Test
    fut = '/container-dir/test.txt'

    # Create the exec and an equivalent event that it will trigger
    test_container.exec_run(f'touch {fut}')

    process = Process(pid=None,
                      uid=0,
                      gid=0,
                      exe_path='/usr/bin/touch',
                      args=f'touch {fut}',
                      name='touch',
                      container_id=test_container.id[:12],
                      loginuid=pow(2, 32)-1)
    events = [
        Event(process=process, event_type=EventType.CREATION,
              file=fut, host_path=''),
        Event(process=process, event_type=EventType.OPEN,
              file=fut, host_path='')
    ]

    for e in events:
        print(f'Waiting for event: {e}')

    server.wait_events(events)


def test_mounted_dir(fact, test_container, ignored_dir, server):
    # File Under Test
    fut = '/mounted/test.txt'

    # Create the exec and an equivalent event that it will trigger
    test_container.exec_run(f'touch {fut}')

    process = Process(pid=None,
                      uid=0,
                      gid=0,
                      exe_path='/usr/bin/touch',
                      args=f'touch {fut}',
                      name='touch',
                      container_id=test_container.id[:12],
                      loginuid=pow(2, 32)-1)
    event = Event(process=process, event_type=EventType.CREATION,
                  file=fut, host_path='')
    print(f'Waiting for event: {event}')

    server.wait_events([event])


def test_unmonitored_mounted_dir(fact, test_container, test_file, server):
    # File Under Test
    fut = '/unmonitored/test.txt'

    # Create the exec and an equivalent event that it will trigger
    test_container.exec_run(f'touch {fut}')

    process = Process(pid=None,
                      uid=0,
                      gid=0,
                      exe_path='/usr/bin/touch',
                      args=f'touch {fut}',
                      name='touch',
                      container_id=test_container.id[:12],
                      loginuid=pow(2, 32)-1)
    event = Event(process=process, event_type=EventType.OPEN,
                  file=fut, host_path=test_file)
    print(f'Waiting for event: {event}')

    server.wait_events([event])
