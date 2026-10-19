from __future__ import annotations

import os
import time
from time import sleep

import docker.models.containers
import pytest
import yaml

from conftest import ENDPOINT_ADDRESS
from event import Event, EventType, Process
from metrics import MetricsSnapshot
from server import EventServer


@pytest.fixture
def rate_limited_config(
    fact: docker.models.containers.Container,
    fact_config: tuple[dict, str],
    monitored_dir: str,
):
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


def test_rate_limit_drops_events(
    rate_limited_config: tuple[dict, str],
    monitored_dir: str,
    server: EventServer,
):
    """
    Test that the rate limiter drops events when the rate limit
    is exceeded.
    """
    num_files = 100

    before = MetricsSnapshot.fetch(ENDPOINT_ADDRESS)

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

    assert received_count < num_files, (
        'Expected rate limiting to drop some events, '
        f'but received all {received_count}'
    )

    after = MetricsSnapshot.fetch(ENDPOINT_ADDRESS)
    delta = before.delta(after)

    delta_dropped = delta.get('rate_limiter_events', {'label': 'Dropped'})
    assert delta_dropped is not None, (
        'rate_limiter_events{label="Dropped"} metric not found'
    )
    dropped_count = int(delta_dropped)

    assert dropped_count > 0, (
        'Expected rate limiter to report dropped events in metrics'
    )

    total_accounted = received_count + dropped_count
    assert total_accounted == num_files, (
        f'Expected received ({received_count}) + dropped '
        f'({dropped_count}) to equal {num_files}, '
        f'got {total_accounted}'
    )


def test_rate_limit_unlimited(
    monitored_dir: str,
    server: EventServer,
    fact_config: tuple[dict, str],
):
    """
    Test that the default config (rate_limit=0) allows all events
    through.
    """
    num_files = 20
    events = []
    process = Process.from_proc()

    before = MetricsSnapshot.fetch(ENDPOINT_ADDRESS)

    for i in range(num_files):
        fut = os.path.join(monitored_dir, f'file_{i}.txt')
        with open(fut, 'w') as f:
            f.write(f'test {i}')

        events.append(
            Event(
                process=process,
                event_type=EventType.CREATION,
                file=fut,
                host_path=fut,
            ),
        )

    server.wait_events(events)

    after = MetricsSnapshot.fetch(ENDPOINT_ADDRESS)
    delta = before.delta(after)

    delta_dropped = delta.get('rate_limiter_events', {'label': 'Dropped'})
    dropped_count = int(delta_dropped) if delta_dropped else 0

    assert dropped_count == 0, (
        'Expected no dropped events with unlimited '
        f'rate limiting, but got {dropped_count}'
    )
