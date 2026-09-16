from __future__ import annotations

import os

import docker
import docker.models.images
import pytest

from containers import pull_or_build


def get_vi_test_file(dir: str):
    return os.path.join(dir, '4913')


@pytest.fixture(scope='session')
def build_editor_image(
    request: pytest.FixtureRequest, docker_client: docker.DockerClient
):
    no_local_builds = bool(request.config.getoption('--no-local-builds'))
    return pull_or_build(
        docker_client,
        tag='fact-editors',
        path='containers/editors',
        no_local_builds=no_local_builds,
    )


def run_editor_container(
    image: str,
    docker_client: docker.DockerClient,
    ignored_dir: str,
):
    container = docker_client.containers.run(
        image,
        detach=True,
        tty=True,
        name='editors',
        volumes={
            ignored_dir: {
                'bind': '/mounted',
                'mode': 'z',
            },
        },
    )
    container.exec_run('mkdir /container-dir')

    yield container

    container.kill()
    container.remove()


@pytest.fixture(scope='session')
def build_fedora_image(
    request: pytest.FixtureRequest, docker_client: docker.DockerClient
) -> docker.models.images.Image:
    no_local_builds = bool(request.config.getoption('--no-local-builds'))
    return pull_or_build(
        docker_client,
        tag='fact-fedora',
        path='containers/fedora',
        no_local_builds=no_local_builds,
    )


@pytest.fixture
def fedora_container(
    docker_client: docker.DockerClient,
    build_fedora_image: docker.models.images.Image,
    ignored_dir: str,
):
    image = build_fedora_image.tags[0]
    yield from run_editor_container(
        image,
        docker_client,
        ignored_dir,
    )


@pytest.fixture
def editor_container(
    build_editor_image: docker.models.images.Image,
    docker_client: docker.DockerClient,
    ignored_dir: str,
):
    image = build_editor_image.tags[0]
    yield from run_editor_container(image, docker_client, ignored_dir)
