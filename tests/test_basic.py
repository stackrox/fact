import os
from time import sleep

from event import Event, Process


def find_event(server, event: Event):
    """
    Continuously checks the server for incoming events until the
    specified event is found.

    Args:
        server: The server instance to retrieve events from.
        event (Event): The event to search for.
    """
    while server.is_running():
        msg = server.get_next()
        if msg is None:
            sleep(0.5)
            continue

        if event == msg:
            break


def test_open(fact, temp_dir, server, executor):
    """
    Tests the opening of a file and verifies that the corresponding
    event is captured by the server.

    Args:
        fact: Fixture for file activity (only required to be running).
        temp_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
        executor: A thread pool executor to run the find_event function
                  concurrently.
    """
    # File Under Test
    fut = os.path.join(temp_dir, 'test.txt')
    with open(fut, 'w') as f:
        f.write('This is a test')

    p = Process(name='pytest', uid=os.getuid(),
                pid=os.getpid(), gid=os.getgid())

    e = Event(process=p, file=fut)

    fs = executor.submit(find_event, server, e)

    fs.result(timeout=5)
