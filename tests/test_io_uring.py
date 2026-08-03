from __future__ import annotations

import os

import docker
import docker.models.containers
import docker.models.images
import pytest

from event import Event, EventType, Process
from server import EventServer


@pytest.fixture(scope='session')
def io_uring_image(docker_client: docker.DockerClient):
    image, _ = docker_client.images.build(
        path='containers/io-uring',
        tag='io-uring:latest',
        dockerfile='Containerfile',
    )
    return image


@pytest.fixture
def get_io_uring_container(
    io_uring_image: docker.models.images.Image,
    docker_client: docker.DockerClient,
    monitored_dir: str,
):
    container = docker_client.containers.run(
        io_uring_image.tags[0],
        detach=True,
        tty=True,
        name='io-uring',
        security_opt=['seccomp=unconfined'],
        volumes={
            monitored_dir: {
                'bind': '/data',
                'mode': 'z',
            },
        },
    )

    yield container

    container.stop(timeout=1)
    container.remove()


def test_io_uring_write(
    monitored_dir: str,
    server: EventServer,
    get_io_uring_container: docker.models.containers.Container,
):
    """
    Verifies that io_uring write operations modify files but are not
    currently tracked by fact.

    Creates a file with 'hi', modifies it to 'bye' via io_uring
    (open, write, and close all go through io_uring, bypassing the
    normal syscall path), then verifies the content changed and that
    only the expected creation events are captured.
    """
    fut = os.path.join(monitored_dir, 'io_uring_test.txt')
    process = Process.from_proc()

    # Create file with initial content via normal I/O.
    with open(fut, 'w') as f:
        f.write('hi')

    creation = Event(
        process=process,
        event_type=EventType.CREATION,
        file=fut,
        host_path=fut,
    )
    server.wait_events([creation])

    # Modify the file using io_uring inside the container.
    exit_code, output = get_io_uring_container.exec_run(
        ['io_uring_write_raw', '/data/io_uring_test.txt', 'bye'],
    )
    if exit_code == 2:
        pytest.skip(f'io_uring not supported: {output.decode()}')
    assert exit_code == 0, f'io_uring write failed: {output.decode()}'

    # Create a sentinel file via normal I/O to verify event ordering.
    # With strict=True (the default), any unexpected event appearing
    # before the sentinel would cause the test to fail.
    sentinel = os.path.join(monitored_dir, 'sentinel.txt')
    with open(sentinel, 'w') as f:
        f.write('sentinel')

    sentinel_event = Event(
        process=process,
        event_type=EventType.CREATION,
        file=sentinel,
        host_path=sentinel,
    )
    server.wait_events([sentinel_event])

    # Verify the file was actually modified by io_uring.
    with open(fut) as f:
        assert f.read() == 'bye'
