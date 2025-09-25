import json
import multiprocessing as mp
import os
import subprocess

import pytest

from event import Event, EventType, Process
from logs import dump_logs


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

    e = Event(process=Process(), event_type=EventType.CREATION, file=fut)
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

        e = Event(process=Process(), event_type=EventType.CREATION, file=fut)
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

    for i in range(3):
        with open(fut, 'a+') as f:
            f.write('This is a test')

        e = Event(process=Process(), file=fut,
                  event_type=EventType.CREATION if i == 0 else EventType.OPEN)
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

    ignored_event = Event(
        process=p, event_type=EventType.CREATION, file=ignored_file)
    print(f'Ignoring: {ignored_event}')

    # File Under Test
    fut = os.path.join(monitored_dir, 'test.txt')
    with open(fut, 'w') as f:
        f.write('This is a test')

    e = Event(process=p, event_type=EventType.CREATION, file=fut)
    print(f'Waiting for event: {e}')

    server.wait_events([e], ignored=[ignored_event])


def test_external_process(fact, monitored_dir, server):
    """
    Tests the opening of a file by an external process and verifies that
    the corresponding event is captured by the server.

    Args:
        fact: Fixture for file activity (only required to be running).
        monitored_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
    """
    def do_test(fut: str, stop_event: mp.Event):
        with open(fut, 'w') as f:
            f.write('This is a test')
        with open(fut, 'a') as f:
            f.write('This is also a test')

        # Wait for test to be done
        stop_event.wait()

    # File Under Test
    fut = os.path.join(monitored_dir, 'test.txt')
    stop_event = mp.Event()
    proc = mp.Process(target=do_test, args=(fut, stop_event))
    proc.start()
    p = Process(proc.pid)

    creation = Event(process=p, event_type=EventType.CREATION, file=fut)
    print(f'Waiting for event: {creation}')
    write_access = Event(process=p, event_type=EventType.OPEN, file=fut)
    print(f'Waiting for event: {write_access}')

    try:
        server.wait_events([creation, write_access])
    finally:
        stop_event.set()
        proc.join(1)


CONTAINER_CMD = 'mkdir -p {monitored_dir}; echo "Some content" > {monitored_dir}/test.txt ; sleep 5'


@pytest.fixture(scope='function')
def test_container(fact, docker_client, monitored_dir, logs_dir):
    image = 'fedora:42'
    command = f"bash -c '{CONTAINER_CMD.format(monitored_dir=monitored_dir)}'"
    container_log = os.path.join(logs_dir, 'fedora.log')
    container = docker_client.containers.run(
        image,
        detach=True,
        command=command,
    )
    yield container
    container.stop(timeout=1)
    container.wait(timeout=1)
    dump_logs(container, container_log)
    container.remove()


def test_container_event(fact, monitored_dir, server, test_container, docker_api_client):
    fut = os.path.join(monitored_dir, 'test.txt')

    inspect = docker_api_client.inspect_container(test_container.id)
    p = Process(pid=inspect['State']['Pid'],
                comm='bash',
                exe_path='/usr/bin/bash',
                args=['bash', '-c',
                      CONTAINER_CMD.format(monitored_dir=monitored_dir)]
                )

    creation = Event(process=p, event_type=EventType.CREATION, file=fut)
    print(f'Waiting for event: {creation}')

    server.wait_events([creation])
