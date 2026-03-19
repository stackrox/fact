"""
Test that verifies inode tracking for newly created files.

Expected behavior:
1. File created in monitored directory
2. BPF adds inode to kernel map (if parent is monitored)
3. Creation event has non-zero inode
4. Subsequent events on that file should also have the inode populated
"""

import os
from tempfile import NamedTemporaryFile

import pytest
import yaml

from event import Event, EventType, Process


@pytest.fixture
def fact_config(monitored_dir, logs_dir):
    """
    Config that includes both the directory and its contents.
    This ensures the parent directory inode is tracked.
    """
    cwd = os.getcwd()
    config = {
        'paths': [f'{monitored_dir}', f'{monitored_dir}/*', f'{monitored_dir}/**', '/mounted/**', '/container-dir/**'],
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


def test_inode_tracking_on_creation(monitored_dir, test_file, server):
    """
    Test that when a file is created in a monitored directory,
    its inode is added to the tracking map.

    The test_file fixture ensures the directory exists and has content
    when fact starts, so the parent directory inode gets tracked.
    """
    # Create a new file
    fut = os.path.join(monitored_dir, 'new_file.txt')
    with open(fut, 'w') as f:
        f.write('initial content')

    # Wait for creation event
    process = Process.from_proc()
    creation_event = Event(process=process, event_type=EventType.CREATION,
                          file=fut, host_path=fut)

    server.wait_events([creation_event])

    # Now modify the file - the inode should be tracked from creation
    with open(fut, 'a') as f:
        f.write('appended content')

    # This open event should have host_path populated because the inode
    # was added to the map during creation
    open_event = Event(process=process, event_type=EventType.OPEN,
                      file=fut, host_path=fut)

    server.wait_events([open_event])
