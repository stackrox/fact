from __future__ import annotations

import os
import time
from time import sleep

import docker.models.containers
import pytest
import yaml

from event import Event, EventType, Process
from server import EventServer
from utils import get_metric_value


@pytest.fixture
def rate_limited_config(
    fact: docker.models.containers.Container,
    fact_config: tuple[dict, str],
    monitored_dir: str,
    server: EventServer,
):
    """
    Configure rate limiting after fact has started, then hot-reload.
    Sets rate_limit to 40 events/second.
    """
    if server.output_mode != 'grpc':
        pytest.skip('rate limiting is only applied to the gRPC output')

    config, config_file = fact_config
    config['grpc']['rate_limit'] = 40
    with open(config_file, 'w') as f:
        yaml.dump(config, f)

    fact.kill('SIGHUP')
    sleep(0.1)
    return config, config_file


def test_rate_limit_throttles_events(
    rate_limited_config: tuple[dict, str],
    monitored_dir: str,
    server: EventServer,
):
    """
    Test that the gRPC rate limiter throttles events when the rate limit
    is exceeded.
    """
    if server.output_mode != 'grpc':
        pytest.skip('rate limiting is only applied to the gRPC output')

    num_files = 100
    events = []
    process = Process.from_proc()
    start_time = time.time()

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

    elapsed = time.time() - start_time
    print(f'Created {num_files} files in {elapsed:.3f} seconds')

    time.sleep(1)

    added_count = get_metric_value(
        rate_limited_config,
        'output_grpc_events',
        {'label': 'Added'},
    )
    assert added_count is not None, (
        'output_grpc_events{label="Added"} metric not found'
    )
    assert int(added_count) < num_files, (
        'Expected the gRPC output to be rate limited, '
        f'but it processed {added_count} events'
    )

    dropped_count = get_metric_value(
        rate_limited_config,
        'output_grpc_events',
        {'label': 'Dropped'},
    )
    assert dropped_count is not None, (
        'output_grpc_events{label="Dropped"} metric not found'
    )
    assert int(dropped_count) == 0, (
        'Expected the rate limiter to throttle rather than drop events, '
        f'but {dropped_count} events were dropped'
    )

    server.wait_events(events)


def test_rate_limit_unlimited(
    monitored_dir: str,
    server: EventServer,
    fact_config: tuple[dict, str],
):
    """
    Test that the default config (rate_limit=0) allows all events through.
    """
    num_files = 20
    events = []
    process = Process.from_proc()

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

    output_metric = {
        'grpc': 'output_grpc_events',
        'otlp': 'output_otel_events',
    }[server.output_mode]
    dropped_count = get_metric_value(
        fact_config,
        output_metric,
        {'label': 'Dropped'},
    )
    assert dropped_count is not None, (
        f'{output_metric}{{label="Dropped"}} metric not found'
    )
    assert int(dropped_count) == 0, (
        'Expected no dropped events with unlimited '
        f'rate limiting, but got {dropped_count}'
    )
