"""Keep observed container paths distinct from monitored host backing paths.

A temporary watched directory stands in for a node policy's /etc. These tests
exercise the output path contract, not Sensor policy evaluation. A matching
container path may still be collected, but must not acquire an unrelated host
path. No real host /etc files are modified.

See https://github.com/stackrox/fact/issues/2130 for the wider policy problem.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator

import docker
import docker.models.containers
import pytest

from event import Event, EventType, Process
from server import EventServer


@pytest.fixture(params=['shadow', 'same-path', 'alias', 'nested-shadow'])
def mount_layout(
    request: pytest.FixtureRequest,
    monitored_dir: str,
    ignored_dir: str,
) -> tuple[dict, str, str, str]:
    # Seed both possible backing locations before Fact's initial inode scan.
    # Existing-file OPEN must work without relying on a prior CREATE event.
    nested = os.path.join(monitored_dir, 'nested')
    os.mkdir(nested)
    for directory in (monitored_dir, nested, ignored_dir):
        with open(os.path.join(directory, 'existing.txt'), 'w') as f:
            f.write(directory)

    watched_mount = {'bind': monitored_dir, 'mode': 'z'}
    match request.param:
        case 'shadow':
            return (
                {ignored_dir: watched_mount},
                monitored_dir,
                ignored_dir,
                '',
            )
        case 'same-path':
            return (
                {monitored_dir: watched_mount},
                monitored_dir,
                monitored_dir,
                monitored_dir,
            )
        case 'alias':
            return (
                {monitored_dir: {'bind': '/unmonitored', 'mode': 'z'}},
                '/unmonitored',
                monitored_dir,
                monitored_dir,
            )
        case 'nested-shadow':
            return (
                {
                    monitored_dir: watched_mount,
                    ignored_dir: {'bind': nested, 'mode': 'z'},
                },
                nested,
                ignored_dir,
                '',
            )
        case _:
            raise AssertionError(f'Unknown mount case: {request.param}')


@pytest.fixture
def fact_config(
    fact_config: tuple[dict, str],
    mount_layout: tuple[dict, str, str, str],
) -> tuple[dict, str]:
    # Force mount_layout's file creation before the autouse Fact fixture starts.
    return fact_config


@pytest.fixture
def writer(
    docker_client: docker.DockerClient,
    mount_layout: tuple[dict, str, str, str],
    logs_dir: str,
) -> Iterator[docker.models.containers.Container]:
    volumes, _, _, _ = mount_layout
    container = docker_client.containers.run(
        'quay.io/fedora/fedora:43',
        command=['sleep', 'infinity'],
        detach=True,
        volumes=volumes,
    )
    try:
        container.reload()
        with open(os.path.join(logs_dir, 'writer-inspect.json'), 'w') as f:
            json.dump(container.attrs, f, indent=2)
        yield container
    finally:
        container.stop(timeout=1)
        container.remove()


@pytest.mark.parametrize('existing', [True, False], ids=['open', 'create'])
def test_container_mount_path_identity(
    mount_layout: tuple[dict, str, str, str],
    writer: docker.models.containers.Container,
    server: EventServer,
    existing: bool,
):
    _, destination, source, expected_host_dir = mount_layout
    filename = 'existing.txt' if existing else 'created.txt'
    observed_path = os.path.join(destination, filename)
    source_path = os.path.join(source, filename)
    expected_host_path = (
        os.path.join(expected_host_dir, filename) if expected_host_dir else ''
    )
    assert writer.id is not None
    command = f'touch {observed_path}'
    result = writer.exec_run(command)
    assert result.exit_code == 0, result.output
    assert os.path.isfile(source_path), 'write must reach the selected source'

    server.wait_events(
        [
            Event(
                process=Process.in_container(
                    exe_path='/usr/bin/touch',
                    args=command,
                    name='touch',
                    container_id=writer.id[:12],
                ),
                event_type=EventType.OPEN if existing else EventType.CREATION,
                file=observed_path,
                host_path=expected_host_path,
            ),
        ]
    )
