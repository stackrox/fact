from __future__ import annotations

import os

import docker
import docker.models.containers
import docker.models.images
import pytest


def get_vi_test_file(dir: str):
    return os.path.join(dir, '4913')


@pytest.fixture(scope='session')
def build_editor_image(docker_client: docker.DockerClient):
    image, _ = docker_client.images.build(
        path='containers/editors',
        tag='editors:latest',
        dockerfile='Containerfile',
    )
    return image


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


@pytest.fixture
def vi_container(docker_client: docker.DockerClient, ignored_dir: str):
    yield from run_editor_container(
        'quay.io/fedora/fedora:43',
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
