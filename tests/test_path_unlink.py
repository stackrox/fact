import multiprocessing as mp
import os

from event import Event, EventType, Process


def test_remove(fact, monitored_dir, server):
    """
    Tests the removal of a file and verifies the corresponding event is
    captured by the server.

    Args:
        fact: Fixture for file activity (only required to be running).
        monitored_dir: Temporary directory path for monitoring the test file.
        server: The server instance to communicate with.
    """
    fut = os.path.join(monitored_dir, 'test.txt')
    with open(fut, 'w') as f:
        f.write('This is a test')
    os.remove(fut)

    process = Process()
    events = [
        Event(process=process, event_type=EventType.CREATION, file=fut),
        Event(process=process, event_type=EventType.UNLINK, file=fut),
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
    process = Process()

    # File Under Test
    for i in range(3):
        fut = os.path.join(monitored_dir, f'{i}.txt')
        with open(fut, 'w') as f:
            f.write('This is a test')
        os.remove(fut)

        events.extend([
            Event(process=process, event_type=EventType.CREATION, file=fut),
            Event(process=process, event_type=EventType.UNLINK, file=fut),
        ])

    server.wait_events(events)


def test_ignored(fact, monitored_dir, ignored_dir, server):
    """
    Tests that unlink events on ignored files are not captured by the
    server.

    Args:
        fact: Fixture for file activity (only required to be running).
        monitored_dir: Temporary directory path for creating the test file.
        ignored_dir: Temporary directory path that is not monitored by fact.
        server: The server instance to communicate with.
    """
    process = Process()

    # Ignored file, must not show up in the server
    ignored_file = os.path.join(ignored_dir, 'test.txt')
    with open(ignored_file, 'w') as f:
        f.write('This is to be ignored')
    os.remove(ignored_file)

    ignored_event = Event(
        process=process, event_type=EventType.UNLINK, file=ignored_file)
    print(f'Ignoring: {ignored_event}')

    # File Under Test
    fut = os.path.join(monitored_dir, 'test.txt')
    with open(fut, 'w') as f:
        f.write('This is a test')
    os.remove(fut)

    e = Event(process=process, event_type=EventType.UNLINK, file=fut)
    print(f'Waiting for event: {e}')

    server.wait_events([e], ignored=[ignored_event])


def test_external_process(fact, monitored_dir, server):
    """
    Tests the removal of a file by an external process and verifies that
    the corresponding event is captured by the server.

    Args:
        fact: Fixture for file activity (only required to be running).
        monitored_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
    """
    def do_test(fut: str, stop_event: mp.Event):
        with open(fut, 'w') as f:
            f.write('This is a test')
        os.remove(fut)

        # Wait for test to be done
        stop_event.wait()

    # File Under Test
    fut = os.path.join(monitored_dir, 'test.txt')
    stop_event = mp.Event()
    proc = mp.Process(target=do_test, args=(fut, stop_event))
    proc.start()
    process = Process(proc.pid)

    removal = Event(process=process, event_type=EventType.UNLINK, file=fut)
    print(f'Waiting for event: {removal}')

    try:
        server.wait_events([removal])
    finally:
        stop_event.set()
        proc.join(1)
