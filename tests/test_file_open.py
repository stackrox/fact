import os
from time import sleep

from event import Event, Process


def test_open(fact, monitored_dir, server):
    """
    Tests the opening of a file and verifies that the corresponding
    event is captured by the server.

    Args:
        fact: Fixture for file activity (only required to be running).
        monitored_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
    """
    # File Under Test
    fut = os.path.join(monitored_dir, 'test.txt')
    with open(fut, 'w') as f:
        f.write('This is a test')

    e = Event(process=Process(), file=fut)
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
    """
    events = []
    # File Under Test
    for i in range(3):
        fut = os.path.join(monitored_dir, f'{i}.txt')
        with open(fut, 'w') as f:
            f.write('This is a test')

        e = Event(process=Process(), file=fut)
        print(f'Waiting for event: {e}')
        events.append(e)

    server.wait_events(events)


def test_multiple_access(fact, monitored_dir, server):
    """
    Tests multiple opening of a file and verifies that the
    corresponding events are captured by the server.

    Args:
        fact: Fixture for file activity (only required to be running).
        monitored_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
    """
    events = []
    # File Under Test
    fut = os.path.join(monitored_dir, 'test.txt')
    e = Event(process=Process(), file=fut)

    for i in range(3):
        with open(fut, 'a+') as f:
            f.write('This is a test')

        print(f'Waiting for event: {e}')
        events.append(e)

    server.wait_events(events)


def test_ignored(fact, monitored_dir, ignored_dir, server):
    """
    Tests that open events on ignored files are not captured by the
    server.

    Args:
        fact: Fixture for file activity (only required to be running).
        monitored_dir: Temporary directory path for creating the test file.
        ignored_dir: Temporary directory path that is not monitored by fact.
        server: The server instance to communicate with.
    """
    p = Process()

    # Ignored file, must not show up in the server
    ignored_file = os.path.join(ignored_dir, 'test.txt')
    with open(ignored_file, 'w') as f:
        f.write('This is to be ignored')

    ignored_event = Event(process=p, file=ignored_file)
    print(f'Ignoring: {ignored_event}')

    # File Under Test
    fut = os.path.join(monitored_dir, 'test.txt')
    with open(fut, 'w') as f:
        f.write('This is a test')

    e = Event(process=p, file=fut)
    print(f'Waiting for event: {e}')

    server.wait_events([e], ignored=[ignored_event])
