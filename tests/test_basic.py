import os
from time import sleep

from event import Event, Process


def find_event(server, event: Event):
    while server.is_running():
        msg = server.get_next()
        if msg is None:
            sleep(0.5)
            continue

        if event == msg:
            break


def test_open(fact, temp_dir, server, executor):
    # File Under Test
    fut = os.path.join(temp_dir, 'test.txt')
    with open(fut, 'w') as f:
        f.write('This is a test')

    p = Process(name='pytest', uid=os.getuid(),
                pid=os.getpid(), gid=os.getgid())

    e = Event(process=p, file=fut)

    fs = executor.submit(find_event, server, e)

    fs.result(timeout=5)
