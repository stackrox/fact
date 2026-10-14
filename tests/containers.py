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


def _is_pull_auth_or_missing_error(e: docker.errors.APIError) -> bool:
    if e.status_code in (401, 403, 404):
        return True

    # Some daemon/registry combinations (e.g. containerd-backed pulls)
    # wrap a registry-level 401/404 in a generic 500 Server Error, only
    # surfacing the real cause in the explanation text.
    explanation = (e.explanation or '').lower()
    return 'unauthorized' in explanation or 'not found' in explanation


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

        if not _is_pull_auth_or_missing_error(e):
            raise e
        print(f'Failed to pull image: {e}')
        print('Attempting to build image from source')

        image, _ = docker_client.images.build(
            path=path, tag=image, dockerfile=containerfile
        )
        return image
