import multiprocessing as mp
import os

import docker

from event import Event, EventType, Process


def test_remove(fact, test_file, server):
    """
    Tests the removal of a file and verifies the corresponding event is
    captured by the server.

    Args:
        fact: Fixture for file activity (only required to be running).
        test_file: Temporary file for testing.
        server: The server instance to communicate with.
    """
    os.remove(test_file)

    process = Process.from_proc()
    events = [
        Event(process=process, event_type=EventType.UNLINK,
              file=test_file, host_path=test_file),
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
                  file=fut, host_path=fut),
            Event(process=process, event_type=EventType.UNLINK,
                  file=fut, host_path=fut),
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
                          file=ignored_file, host_path=ignored_file)
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
                    file=fut, host_path=fut)
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
    inspect = docker.APIClient().inspect_container(test_container.id)
    upper_dir = inspect['GraphDriver']['Data']['UpperDir']

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


def test_mounted_dir(fact, test_container, monitored_dir, server):
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
        Event(process=touch, event_type=EventType.OPEN, file=fut,
              host_path=os.path.join(monitored_dir, 'test.txt')),
        Event(process=rm, event_type=EventType.UNLINK, file=fut,
              host_path=os.path.join(monitored_dir, 'test.txt')),
    ]

    for e in events:
        print(f'Waiting for event: {e}')

    server.wait_events(events)
