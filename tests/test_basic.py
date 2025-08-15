import os
from time import sleep

from event import Event, Process


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

    fs = executor.submit(server.wait_event, e)

    fs.result(timeout=5)
