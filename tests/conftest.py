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
    s = FileActivityService()
    s.serve()
    yield s
    s.stop()


@pytest.fixture
def fact(docker_client, temp_dir, server):
    command = ['http://127.0.0.1:9999', '-p', temp_dir]
    container = docker_client.containers.run(
        'fact:latest',
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
        },
    )

    # Wait for container to be ready
    for _ in range(3):
        try:
            resp = requests.get('http://127.0.0.1:9000')
            if resp.status_code == 200:
                break
        except Exception as e:
            print(e)
        sleep(1)
    else:
        container.stop(timeout=1)
        print(container.logs().decode('utf-8'))
        container.remove()
        pytest.fail('fact failed to start')

    yield container

    container.stop(timeout=1)
    exit_status = container.wait(timeout=1)
    logs = container.logs().decode('utf-8')
    print(logs)
    container.remove()
    assert exit_status['StatusCode'] == 0


@pytest.fixture
def executor():
    return futures.ThreadPoolExecutor(max_workers=2)
