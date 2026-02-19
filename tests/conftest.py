import os
from shutil import rmtree
from tempfile import NamedTemporaryFile, mkdtemp
from time import sleep

import docker
import pytest
import requests
import yaml

from server import FileActivityService


# Declare files holding fixtures
pytest_plugins = [
    'test_editors.commons'
]


def join_path_with_filename(directory, filename):
    """
    Join a directory path with a filename, handling bytes filenames properly.

    When filename is bytes (e.g., containing invalid UTF-8), converts the
    directory to bytes before joining to avoid mixing str and bytes.

    Args:
        directory: Directory path (str)
        filename: Filename (str or bytes)

    Returns:
        Joined path (str or bytes, matching the filename type)
    """
    if isinstance(filename, bytes):
        return os.path.join(os.fsencode(directory), filename)
    else:
        return os.path.join(directory, filename)


def path_to_string(path):
    """
    Convert a filesystem path to string, replacing invalid UTF-8 with U+FFFD.

    This matches the behavior of Rust's String::from_utf8_lossy() used in
    the fact codebase.

    Args:
        path: Filesystem path (str or bytes)

    Returns:
        String representation with invalid UTF-8 replaced by replacement character
    """
    if isinstance(path, bytes):
        return path.decode('utf-8', errors='replace')
    else:
        return path


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
def test_file(monitored_dir):
    """
    Create a temporary file for tests

    This file needs to exist when fact starts up for the inode tracking
    algorithm to work.
    """
    fut = os.path.join(monitored_dir, 'test.txt')
    with open(fut, 'w') as f:
        f.write('test')
    yield fut


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
def fact_config(request, monitored_dir, logs_dir):
    cwd = os.getcwd()
    config = {
        'paths': [monitored_dir, '/mounted', '/container-dir'],
        'grpc': {
            'url': 'http://127.0.0.1:9999',
        },
        'endpoint': {
            'address': '127.0.0.1:9000',
            'expose_metrics': True,
            'health_check': True,
        },
        'json': True,
    }
    config_file = NamedTemporaryFile(
        prefix='fact-config-', suffix='.yml', dir=cwd, mode='w')
    yaml.dump(config, config_file)

    yield config, config_file.name
    with open(os.path.join(logs_dir, 'fact.yml'), 'w') as f:
        with open(config_file.name, 'r') as r:
            f.write(r.read())
    config_file.close()


@pytest.fixture
def test_container(request, docker_client, monitored_dir, ignored_dir):
    """
    Run a container for triggering events in.
    """
    container = docker_client.containers.run(
        'quay.io/fedora/fedora:43',
        detach=True,
        tty=True,
        volumes={
            ignored_dir: {
                'bind': '/mounted',
                'mode': 'z',
            },
            monitored_dir: {
                'bind': '/unmonitored',
                'mode': 'z',
            }
        },
        name='fedora',
    )
    container.exec_run('mkdir /container-dir')

    yield container

    container.stop(timeout=1)
    container.remove()


@pytest.fixture(autouse=True)
def fact(request, docker_client, fact_config, server, logs_dir, test_file):
    """
    Run the fact docker container for integration tests.
    """
    config, config_file = fact_config
    image = request.config.getoption('--image')
    container = docker_client.containers.run(
        image,
        detach=True,
        environment={
            'FACT_LOGLEVEL': 'debug',
            'FACT_HOST_MOUNT': '/host',
        },
        name='fact',
        network_mode='host',
        privileged=True,
        volumes={
            '/': {
                'bind': '/host',
                'mode': 'ro',
            },
            config_file: {
                'bind': '/etc/stackrox/fact.yml',
                'mode': 'ro',
            }
        },
    )

    container_log = os.path.join(logs_dir, 'fact.log')
    # Wait for container to be ready
    for _ in range(3):
        try:
            resp = requests.get(
                f'http://{config["endpoint"]["address"]}/health_check')
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
    if config['endpoint']['expose_metrics']:
        metric_log = os.path.join(logs_dir, 'metrics')
        resp = requests.get(
            f'http://{config["endpoint"]["address"]}/metrics')
        if resp.status_code == 200:
            with open(metric_log, 'w') as f:
                f.write(resp.text)

    container.stop(timeout=2)
    exit_status = container.wait(timeout=2)
    dump_logs(container, container_log)
    container.remove()
    assert exit_status['StatusCode'] == 0


def pytest_addoption(parser):
    parser.addoption('--image', action='store', default='quay.io/stackrox-io/fact:latest',
                     help='The image to be used for testing')
