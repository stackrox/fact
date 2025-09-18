from concurrent import futures
import os
from shutil import rmtree
from tempfile import mkdtemp
from time import sleep

import docker
import pytest
import requests

from server import FileActivityService


@pytest.fixture
def monitored_dir():
    """
    Create a temporary directory for tests and clean it up afterwards.
    """
    cwd = os.getcwd()
    tmp = mkdtemp(prefix='fact-test-', dir=cwd)
    yield tmp
    rmtree(tmp)


@pytest.fixture
def ignored_dir():
    """
    Create a temporary directory for tests that will not be monitored
    by fact. After tests are done, the directory is cleaned up.
    """
    cwd = os.getcwd()
    tmp = mkdtemp(prefix='fact-test-', dir=cwd)
    yield tmp
    rmtree(tmp)


@pytest.fixture(scope='session', autouse=True)
def docker_client():
    """
    Create a docker client to be used by the tests.

    Returns:
        A docker.DockerClient object created from the environment the
        tests run on.
    """
    return docker.from_env()


@pytest.fixture
def server():
    """
    Fixture to start and stop the FileActivityService.
    """
    s = FileActivityService()
    s.serve()
    yield s
    s.stop()


@pytest.fixture
def logs_dir(request):
    logs = os.path.join(os.getcwd(), 'logs',
                        request.module.__name__, request.node.name)
    os.makedirs(logs, exist_ok=True)
    return logs


@pytest.fixture(scope='session', autouse=True)
def get_image(request, docker_client):
    image = request.config.getoption('--image')
    try:
        docker_client.images.get(image)
    except docker.errors.ImageNotFound:
        docker_client.images.pull(image)


def dump_logs(container, file):
    logs = container.logs().decode('utf-8')
    with open(file, 'w') as f:
        f.write(logs)


@pytest.fixture
def fact(request, docker_client, monitored_dir, server, logs_dir):
    """
    Run the fact docker container for integration tests.
    """
    command = [
        'http://127.0.0.1:9999',
        '-p', monitored_dir,
        '--health-check',
        '--json',
    ]
    image = request.config.getoption('--image')
    container = docker_client.containers.run(
        image,
        command=command,
        detach=True,
        environment={
            'FACT_LOGLEVEL': 'debug',
            'FACT_HOST_MOUNT': '/host',
        },
        name='fact',
        network_mode='host',
        privileged=True,
        volumes={
            '/sys/kernel/security': {
                'bind': '/host/sys/kernel/security',
                'mode': 'ro',
            },
            '/etc': {
                'bind': '/host/etc',
                'mode': 'ro',
            },
            '/proc/sys/kernel': {
                'bind': '/host/proc/sys/kernel',
                'mode': 'ro',
            },
            '/usr/lib/os-release': {
                'bind': '/host/usr/lib/os-release',
                'mode': 'ro',
            },
        },
    )

    container_log = os.path.join(logs_dir, 'fact.log')
    # Wait for container to be ready
    for _ in range(3):
        try:
            resp = requests.get('http://127.0.0.1:9000')
            if resp.status_code == 200:
                break
        except (requests.RequestException, requests.ConnectionError) as e:
            print(e)
        sleep(1)
    else:
        container.stop(timeout=1)
        dump_logs(container, container_log)
        container.remove()
        pytest.fail('fact failed to start')

    yield container

    # Capture prometheus metrics before stopping the container
    metric_log = os.path.join(logs_dir, 'metrics')
    resp = requests.get('http://127.0.0.1:9001')
    if resp.status_code == 200:
        with open(metric_log, 'w') as f:
            f.write(resp.text)

    container.stop(timeout=1)
    exit_status = container.wait(timeout=1)
    dump_logs(container, container_log)
    container.remove()
    assert exit_status['StatusCode'] == 0


def pytest_addoption(parser):
    parser.addoption('--image', action='store', default='quay.io/stackrox-io/fact:latest',
                     help='The image to be used for testing')
