import os

from conftest import dump_logs
from containers import pull_or_build
from event import Event, EventType, Process

import pytest


@pytest.fixture(scope='session')
def build_self_deleter(request: pytest.FixtureRequest, docker_client):
    no_local_builds = bool(request.config.getoption('--no-local-builds'))
    return pull_or_build(
        docker_client,
        tag='fact-self-deleter',
        path='containers/self-deleter',
        no_local_builds=no_local_builds,
    )


@pytest.fixture
def run_self_deleter(fact, monitored_dir, logs_dir, docker_client, build_self_deleter):
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


def test_d_path_sanitization(monitored_dir, server, run_self_deleter, docker_client):
    """
    Ensure the sanitization of paths obtained by calling the bpf_d_path
    helper don't include the " (deleted)" suffix when the file is
    removed.
    """
    # File Under Test
    fut = '/mounted/test.txt'
    host_path = os.path.join(monitored_dir, 'test.txt')

    container = run_self_deleter

    process = Process.in_container(
        exe_path='/usr/local/bin/self-deleter',
        args=f'self-deleter {fut}',
        name='self-deleter',
        container_id=container.id[:12],
    )
    event = Event(process=process, event_type=EventType.OPEN,
                  file=fut, host_path=host_path)

    server.wait_events([event])
