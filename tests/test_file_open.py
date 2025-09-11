import os
from time import sleep

from event import Event, Process


def test_open(fact, monitored_dir, server, executor):
    """
    Tests the opening of a file and verifies that the corresponding
    event is captured by the server.

    Args:
        fact: Fixture for file activity (only required to be running).
        monitored_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
        executor: A thread pool executor to run the wait_events function
                  concurrently.
    """
    # File Under Test
    fut = os.path.join(monitored_dir, 'test.txt')
    with open(fut, 'w') as f:
        f.write('This is a test')

    e = Event(process=Process(), file=fut)
    print(f'Waiting for event: {e}')

    fs = executor.submit(server.wait_events, [e])

    fs.result(timeout=5)


def test_multiple(fact, monitored_dir, server, executor):
    """
    Tests the opening of multiple files and verifies that the
    corresponding events are captured by the server.

    Args:
        fact: Fixture for file activity (only required to be running).
        monitored_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
        executor: A thread pool executor to run the wait_events function
                  concurrently.
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

    fs = executor.submit(server.wait_events, events)

    fs.result(timeout=5)


def test_ignored(fact, monitored_dir, ignored_dir, server, executor):
    """
    Tests that open events on ignored files are not captured by the
    server.

    Args:
        fact: Fixture for file activity (only required to be running).
        temp_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
        executor: A thread pool executor to run the wait_events function
                  concurrently.
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

    fs = executor.submit(server.wait_events, [e], ignored=[ignored_event])

    fs.result(timeout=5)
