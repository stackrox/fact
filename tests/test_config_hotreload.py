import os
from time import sleep

from event import Event, EventType, Process

import pytest
import requests
import yaml

from server import FileActivityService

DEFAULT_URL = 'http://127.0.0.1:9000'


def assert_endpoint(endpoint, status_code=200):
    resp = requests.get(f'{DEFAULT_URL}/{endpoint}')
    assert resp.status_code == status_code


def reload_config(fact, config, file, delay=0.1):
    with open(file, 'w') as f:
        yaml.dump(config, f)
    fact.kill('SIGHUP')
    sleep(delay)


cases = [('metrics', 'expose_metrics'), ('health_check', 'health_check')]


@pytest.mark.parametrize('case', cases, ids=['metrics', 'health_check'])
def test_endpoint(fact, fact_config, case):
    """
    Test the endpoints configurability
    """
    endpoint, field = case

    # Endpoints are assumed to start up enabled.
    assert_endpoint(endpoint)

    # Mark the endpoint as off and reload configuration
    config, config_file = fact_config
    config['endpoint'][field] = False
    reload_config(fact, config, config_file)

    assert_endpoint(endpoint, 503)


def test_endpoint_disable_all(fact, fact_config):
    """
    Disable all endpoints and check the default port is not bound
    """
    config, config_file = fact_config
    config['endpoint'] = {
        'health_check': False,
        'expose_metrics': False,
    }
    reload_config(fact, config, config_file)

    with pytest.raises(requests.ConnectionError):
        requests.get(f'{DEFAULT_URL}/metrics')


def test_endpoint_address_change(fact, fact_config):
    config, config_file = fact_config
    config['endpoint']['address'] = '127.0.0.1:9001'
    reload_config(fact, config, config_file)

    with pytest.raises(requests.ConnectionError):
        requests.get(f'{DEFAULT_URL}/metrics')

    resp = requests.get('http://127.0.0.1:9001/metrics')
    assert resp.status_code == 200


ALTERNATE_PORT = '9998'


@pytest.fixture
def alternate_server():
    """
    Fixture to start and stop a FileActivityService on an alternate
    address.
    """
    s = FileActivityService()
    s.serve(f'0.0.0.0:{ALTERNATE_PORT}')
    yield s
    s.stop()


def test_output_grpc_address_change(fact, fact_config, monitored_dir, server, alternate_server):
    """
    Tests we can receive events on a new endpoint after a configuration
    change.
    """
    # File Under Test
    fut = os.path.join(monitored_dir, 'test2.txt')
    with open(fut, 'w') as f:
        f.write('This is a test')

    process = Process.from_proc()
    e = Event(process=process, event_type=EventType.CREATION,
              file=fut, host_path='')

    server.wait_events([e])

    # Change to the alternate server and trigger an event there.
    config, config_file = fact_config
    config['grpc']['url'] = f'http://127.0.0.1:{ALTERNATE_PORT}'
    reload_config(fact, config, config_file)

    with open(fut, 'w') as f:
        f.write('This is another test')

    e = Event(process=process, event_type=EventType.OPEN,
              file=fut, host_path='')

    alternate_server.wait_events([e])


def test_paths(fact, fact_config, monitored_dir, ignored_dir, server):
    p = Process.from_proc()

    # Ignored file, must not show up in the server
    ignored_file = os.path.join(ignored_dir, 'test.txt')
    with open(ignored_file, 'w') as f:
        f.write('This is to be ignored')

    # File Under Test
    fut = os.path.join(monitored_dir, 'test2.txt')
    with open(fut, 'w') as f:
        f.write('This is a test')

    e = Event(process=p, event_type=EventType.CREATION,
              file=fut, host_path='')

    server.wait_events([e])

    config, config_file = fact_config
    config['paths'] = [ignored_dir]
    reload_config(fact, config, config_file, delay=0.5)

    # At this point, the event in the ignored directory should show up
    # and the event on the monitored directory should be ignored
    with open(ignored_file, 'w') as f:
        f.write('This is another test')

    e = Event(process=p, event_type=EventType.OPEN,
              file=ignored_file, host_path='')

    # File Under Test
    with open(fut, 'w') as f:
        f.write('This is another ignored event')

    server.wait_events([e])


def test_paths_addition(fact, fact_config, monitored_dir, ignored_dir, server):
    p = Process.from_proc()

    # Ignored file, must not show up in the server
    ignored_file = os.path.join(ignored_dir, 'test.txt')
    with open(ignored_file, 'w') as f:
        f.write('This is to be ignored')

    # File Under Test
    fut = os.path.join(monitored_dir, 'test2.txt')
    with open(fut, 'w') as f:
        f.write('This is a test')

    e = Event(process=p, event_type=EventType.CREATION,
              file=fut, host_path='')

    server.wait_events([e])

    config, config_file = fact_config
    config['paths'] = [monitored_dir, ignored_dir]
    reload_config(fact, config, config_file, delay=0.5)

    # At this point, the event in the ignored directory should show up
    # alongside the regular event
    with open(ignored_file, 'w') as f:
        f.write('This is another test')
    with open(fut, 'w') as f:
        f.write('This is one final event')

    events = [
        Event(process=p, event_type=EventType.OPEN,
              file=ignored_file, host_path=''),
        Event(process=p, event_type=EventType.OPEN, file=fut, host_path='')
    ]

    server.wait_events(events)
