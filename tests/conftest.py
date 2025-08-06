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
def temp_dir():
    """
    Create a temporary directory for tests and clean it up afterwards.
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
    logs = os.path.join(os.getcwd(), 'logs', request.node.name)
    os.makedirs(logs, exist_ok=True)
    return logs


@pytest.fixture(scope='session', autouse=True)
def get_image(request, docker_client):
    tag = request.config.getoption('--tag')
    image = f'quay.io/rhacs-eng/fact:{tag}'
    try:
        docker_client.images.get(image)
    except docker.errors.ImageNotFound:
        docker_client.images.pull(image)


def dump_logs(container, file):
    logs = container.logs().decode('utf-8')
    with open(file, 'w') as f:
        f.write(logs)


@pytest.fixture
def fact(request, docker_client, temp_dir, server, logs_dir):
    """
    Run the fact docker container for integration tests.
    """
    command = [
        'http://127.0.0.1:9999',
        '-p', temp_dir,
        '--health-check',
    ]
    tag = request.config.getoption('--tag')
    container = docker_client.containers.run(
        f'quay.io/rhacs-eng/fact:{tag}',
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
        },
    )
    log_file = os.path.join(logs_dir, 'fact.log')

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
        dump_logs(container, log_file)
        container.remove()
        pytest.fail('fact failed to start')

    yield container

    container.stop(timeout=1)
    exit_status = container.wait(timeout=1)
    dump_logs(container, log_file)
    container.remove()
    assert exit_status['StatusCode'] == 0


@pytest.fixture
def executor():
    """
    Fixture that provides a ThreadPoolExecutor for concurrent operations
    in tests.
    """
    return futures.ThreadPoolExecutor(max_workers=2)


def pytest_addoption(parser):
    parser.addoption('--tag', action='store', default='latest',
                     help='The tag to be used for testing')
