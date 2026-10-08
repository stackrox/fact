from __future__ import annotations

import os

import docker
import docker.errors
from docker.models.images import Image


def read_qa_tag() -> str:
    tag = os.environ.get('FACT_QA_TAG')
    if tag is not None:
        return tag

    with open('containers/QA_TAG') as f:
        return f.read().strip()


QA_TAG = read_qa_tag()
QA_REPOSITORY = os.environ.get(
    'FACT_QA_REPOSITORY', 'quay.io/rhacs-eng/qa-multi-arch'
)


def pull_or_build(
    docker_client: docker.DockerClient,
    tag: str,
    path: str | None,
    no_local_builds: bool,
    containerfile: str = 'Containerfile',
) -> Image:
    tag = f'{tag}-{QA_TAG}'
    image = f'{QA_REPOSITORY}:{tag}'

    try:
        return docker_client.images.get(image)
    except docker.errors.ImageNotFound:
        print(f'{image} not found locally, attempting to pull')

    try:
        return docker_client.images.pull(QA_REPOSITORY, tag=tag)
    except docker.errors.APIError as e:
        if no_local_builds:
            raise e

        if e.status_code != 401 and e.status_code != 404:
            raise e
        print(f'Failed to pull image: {e}')
        print('Attempting to build image from source')

        image, _ = docker_client.images.build(
            path=path, tag=image, dockerfile=containerfile
        )
        return image
