from time import sleep
import pytest
import requests
import yaml

DEFAULT_URL = 'http://127.0.0.1:9000'


def assert_endpoint(endpoint, status_code=200):
    resp = requests.get(f'{DEFAULT_URL}/{endpoint}')
    assert resp.status_code == status_code


def reload_config(fact, config, file):
    with open(file, 'w') as f:
        yaml.dump(config, f)
    fact.kill('SIGHUP')
    sleep(0.1)


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
