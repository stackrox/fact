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
    Verifies that io_uring write operations are tracked by fact.

    Creates a file with 'hi', modifies it to 'bye' via io_uring
    (open, write, and close all go through io_uring, bypassing the
    normal syscall path), then verifies the content changed and that
    the io_uring file open is captured via the file_open LSM hook.
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
    # Use the low-level Docker API to obtain the exec PID, which
    # appears in the io_uring worker thread name (iou-wrk-<pid>).
    container = get_io_uring_container
    assert container.id is not None
    cmd = ['io_uring_write_raw', '/data/io_uring_test.txt', 'bye']
    exec_id = container.client.api.exec_create(container.id, cmd)['Id']
    output = container.client.api.exec_start(exec_id)
    exec_info = container.client.api.exec_inspect(exec_id)
    exit_code = exec_info['ExitCode']
    exec_pid = exec_info['Pid']

    if exit_code == 2:
        pytest.skip(f'io_uring not supported: {output.decode()}')
    assert exit_code == 0, f'io_uring write failed: {output.decode()}'

    # The io_uring OPENAT operation triggers the file_open LSM hook.
    # io_uring offloads blocking ops to worker threads named
    # iou-wrk-<pid>, where pid is the owning process PID.
    io_uring_process = Process.in_container(
        exe_path='/usr/local/bin/io_uring_write_raw',
        args='io_uring_write_raw /data/io_uring_test.txt bye',
        name=f'iou-wrk-{exec_pid}',
        container_id=container.id[:12],
    )
    io_uring_open = Event(
        process=io_uring_process,
        event_type=EventType.OPEN,
        file='/data/io_uring_test.txt',
        host_path=fut,
    )
    # Create a sentinel file via normal I/O to verify event ordering.
    sentinel = os.path.join(monitored_dir, 'sentinel.txt')
    with open(sentinel, 'w') as f:
        f.write('sentinel')

    sentinel_event = Event(
        process=process,
        event_type=EventType.CREATION,
        file=sentinel,
        host_path=sentinel,
    )
    server.wait_events([io_uring_open, sentinel_event])

    # Verify the file was actually modified by io_uring.
    with open(fut) as f:
        assert f.read() == 'bye'
