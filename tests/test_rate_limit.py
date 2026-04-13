import os
import time
from time import sleep

import pytest
import requests
import yaml

from event import Event, EventType, Process

@pytest.fixture
def rate_limited_config(fact, fact_config, monitored_dir):
    """
    Configure rate limiting after fact has started, then hot-reload.
    Sets rate_limit to 10 events/second.
    """
    config, config_file = fact_config
    config['rate_limit'] = 10
    with open(config_file, 'w') as f:
        yaml.dump(config, f)

    fact.kill('SIGHUP')
    sleep(0.1)
    return config, config_file

def test_rate_limit_drops_events(rate_limited_config, monitored_dir, server):
    """
    Test that the rate limiter drops events when the rate limit is exceeded.
    """
    config, _ = rate_limited_config
    num_files = 100
    start_time = time.time()

    for i in range(num_files):
        fut = os.path.join(monitored_dir, f'file_{i}.txt')
        with open(fut, 'w') as f:
            f.write(f'test {i}')

    elapsed = time.time() - start_time
    print(f'Created {num_files} files in {elapsed:.3f} seconds')

    time.sleep(2)

    received_count = 0
    while not server.is_empty():
        server.get_next()
        received_count += 1

    print(f'Received {received_count} events out of {num_files}')

    assert received_count < num_files, \
        f'Expected rate limiting to drop some events, but received all {received_count}'

    metrics_response = requests.get(f'http://{config["endpoint"]["address"]}/metrics')
    assert metrics_response.status_code == 200

    metrics_text = metrics_response.text
    assert 'rate_limiter_events' in metrics_text, 'rate_limiter_events metric not found'

    dropped_count = 0
    for line in metrics_text.split('\n'):
        if 'rate_limiter_events' in line and 'label="Dropped"' in line:
            parts = line.split()
            if len(parts) >= 2:
                dropped_count = int(parts[1])
                break

    assert dropped_count > 0, 'Expected rate limiter to report dropped events in metrics'

    total_accounted = received_count + dropped_count

    assert total_accounted >= num_files - 5, \
        f'Too many unaccounted events: received={received_count}, dropped={dropped_count}, created={num_files}'

def test_rate_limit_unlimited(monitored_dir, server, fact_config):
    """
    Test that the default config (rate_limit=0) allows all events through.
    """
    config, _ = fact_config
    num_files = 20
    events = []
    process = Process.from_proc()

    for i in range(num_files):
        fut = os.path.join(monitored_dir, f'file_{i}.txt')
        with open(fut, 'w') as f:
            f.write(f'test {i}')

        events.append(
            Event(process=process, event_type=EventType.CREATION, file=fut, host_path=fut))

    server.wait_events(events)

    metrics_response = requests.get(f'http://{config["endpoint"]["address"]}/metrics')
    assert metrics_response.status_code == 200

    metrics_text = metrics_response.text

    dropped_count = 0
    for line in metrics_text.split('\n'):
        if 'rate_limiter_events' in line and 'label="Dropped"' in line:
            parts = line.split()
            if len(parts) >= 2:
                dropped_count = int(parts[1])
                break

    assert dropped_count == 0, \
        f'Expected no dropped events with unlimited rate limiting, but got {dropped_count}'
