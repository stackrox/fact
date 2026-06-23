from __future__ import annotations

import os
import subprocess
from shutil import rmtree
from tempfile import NamedTemporaryFile, mkdtemp
from time import sleep

import docker
import docker.errors
import docker.models.containers
import pytest
import requests
import yaml

from event import Event, EventType, Process
from server import FileActivityService


def get_dockerd_process() -> Process | None:
    result = subprocess.run(
        ['pgrep', 'dockerd'],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    pid = int(result.stdout.strip().split('\n')[0])
    proc = Process.from_proc(pid)
    # Process.from_proc uses os.path.realpath on /proc/<pid>/exe,
    # which may not resolve across mount namespaces (e.g. CoreOS).
    # Use the path from pgrep -a instead.
    result = subprocess.run(
        ['pgrep', '-a', 'dockerd'],
        capture_output=True,
        text=True,
    )
    exe_path = result.stdout.strip().split('\n')[0].split()[1]
    return Process(
        pid=None,
        uid=proc.uid,
        gid=proc.gid,
        exe_path=exe_path,
        args=proc.args,
        name=proc.name,
        container_id=proc.container_id,
        loginuid=proc.loginuid,
    )


# Declare files holding fixtures
pytest_plugins = ['test_editors.commons']


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
def test_file(monitored_dir: str):
    """
    Create a temporary file for tests

    This file needs to exist when fact starts up for the inode tracking
    algorithm to work.
    """
    fut = os.path.join(monitored_dir, 'test.txt')
    with open(fut, 'w') as f:
        f.write('test')
    return fut


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
def logs_dir(request: pytest.FixtureRequest):
    logs = os.path.join(
        os.getcwd(),
        'logs',
        request.module.__name__,
        request.node.name,
    )
    os.makedirs(logs, exist_ok=True)
    return logs


@pytest.fixture(scope='session', autouse=True)
def get_image(
    request: pytest.FixtureRequest,
    docker_client: docker.DockerClient,
):
    image = request.config.getoption('--image')
    assert isinstance(image, str)
    try:
        docker_client.images.get(image)
    except docker.errors.ImageNotFound:
        docker_client.images.pull(image)


def dump_logs(container: docker.models.containers.Container, file: str):
    logs = container.logs().decode('utf-8')
    with open(file, 'w') as f:
        f.write(logs)


@pytest.fixture
def fact_config(
    request: pytest.FixtureRequest,
    monitored_dir: str,
    logs_dir: str,
):
    cwd = os.getcwd()
    config = {
        'paths': [
            f'{monitored_dir}',
            f'{monitored_dir}/**/*',
            '/mounted/**/*',
            '/container-dir/**/*',
        ],
        'grpc': {
            'url': 'http://127.0.0.1:9999',
        },
        'endpoint': {
            'address': '127.0.0.1:9000',
            'expose_metrics': True,
            'health_check': True,
        },
        'json': True,
        'scan_interval': 0,
    }
    config_file = NamedTemporaryFile(  # noqa: SIM115
        prefix='fact-config-',
        suffix='.yml',
        dir=cwd,
        mode='w',
    )
    yaml.dump(config, config_file)

    yield config, config_file.name
    with (
        open(os.path.join(logs_dir, 'fact.yml'), 'w') as f,
        open(config_file.name) as r,
    ):
        f.write(r.read())
    config_file.close()


@pytest.fixture
def test_container(
    request: pytest.FixtureRequest,
    docker_client: docker.DockerClient,
    monitored_dir: str,
    ignored_dir: str,
):
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
            },
        },
        name='fedora',
    )
    container.exec_run('mkdir /container-dir')

    yield container

    container.stop(timeout=1)
    container.remove()


@pytest.fixture
def docker_selinux_xattr(
    docker_client: docker.DockerClient,
    monitored_dir: str,
    test_file: str,
) -> list[Event]:
    """
    Expected xattr events from Docker SELinux relabeling.

    When Docker creates a container with ':z' volume mounts, it
    relabels files with security.selinux. This fixture returns the
    expected events if Docker has SELinux enabled, or an empty list
    otherwise.

    Docker relabels both the file and its parent directory.
    """
    info = docker_client.info()
    selinux = any('selinux' in opt for opt in info.get('SecurityOptions', []))
    if not selinux:
        return []
    dockerd = get_dockerd_process()
    if dockerd is None:
        return []
    return [
        Event(
            process=dockerd,
            event_type=EventType.XATTR_SET,
            file='',
            host_path=test_file,
            xattr_name='security.selinux',
        ),
        Event(
            process=dockerd,
            event_type=EventType.XATTR_SET,
            file='',
            host_path=monitored_dir,
            xattr_name='security.selinux',
        ),
    ]


@pytest.fixture(autouse=True)
def fact(
    request: pytest.FixtureRequest,
    docker_client: docker.DockerClient,
    fact_config: tuple[dict, str],
    server: FileActivityService,
    logs_dir: str,
    test_file: str,
):
    """
    Run the fact docker container for integration tests.
    """
    config, config_file = fact_config
    image = request.config.getoption('--image')
    assert isinstance(image, str)
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
            },
        },
    )

    container_log = os.path.join(logs_dir, 'fact.log')
    # Wait for container to be ready
    for _ in range(3):
        try:
            resp = requests.get(
                f'http://{config["endpoint"]["address"]}/health_check'
            )
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
        resp = requests.get(f'http://{config["endpoint"]["address"]}/metrics')
        if resp.status_code == 200:
            with open(metric_log, 'w') as f:
                f.write(resp.text)

    container.stop(timeout=2)
    exit_status = container.wait(timeout=2)
    dump_logs(container, container_log)
    container.remove()
    assert exit_status['StatusCode'] == 0


def pytest_addoption(parser: pytest.Parser):
    parser.addoption(
        '--image',
        action='store',
        default='quay.io/stackrox-io/fact:latest',
        help='The image to be used for testing',
    )
