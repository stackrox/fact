from __future__ import annotations

import os

import docker
import docker.models.containers
import docker.models.images
import pytest

from conftest import dump_logs
from event import Event, EventType, Process
from server import FileActivityService


@pytest.fixture
def build_self_deleter(docker_client: docker.DockerClient):
    image, _ = docker_client.images.build(
        path='containers/self-deleter',
        tag='self-deleter:latest',
        dockerfile='Containerfile',
    )
    return image


@pytest.fixture
def run_self_deleter(
    fact: docker.models.containers.Container,
    monitored_dir: str,
    logs_dir: str,
    docker_client: docker.DockerClient,
    build_self_deleter: docker.models.images.Image,
):
    image = build_self_deleter.tags[0]
    container = docker_client.containers.run(
        image,
        '/mounted/test.txt',
        detach=True,
        volumes={
            monitored_dir: {
                'bind': '/mounted',
                'mode': 'z',
            },
        },
        name='self-deleter',
    )

    yield container

    container_log = os.path.join(logs_dir, 'self-deleter.log')
    container.stop(timeout=1)
    dump_logs(container, container_log)
    container.remove()


def test_d_path_sanitization(
    monitored_dir: str,
    server: FileActivityService,
    run_self_deleter: docker.models.containers.Container,
    docker_client: docker.DockerClient,
    docker_selinux_xattr: list[Event],
):
    """
    Ensure the sanitization of paths obtained by calling the bpf_d_path
    helper don't include the " (deleted)" suffix when the file is
    removed.
    """
    # File Under Test
    fut = '/mounted/test.txt'
    host_path = os.path.join(monitored_dir, 'test.txt')

    container = run_self_deleter
    assert container.id is not None

    process = Process.in_container(
        exe_path='/usr/local/bin/self-deleter',
        args=f'self-deleter {fut}',
        name='self-deleter',
        container_id=container.id[:12],
    )
    event = Event(
        process=process,
        event_type=EventType.OPEN,
        file=fut,
        host_path=host_path,
    )

    server.wait_events([*docker_selinux_xattr, event])
