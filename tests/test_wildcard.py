from time import sleep
import os

import pytest
import yaml

from event import Event, EventType, Process


@pytest.fixture
def wildcard_config(fact, fact_config, monitored_dir):
    config, config_file = fact_config
    config['paths'] = [
        f'{monitored_dir}/**/*.txt',
        f'{monitored_dir}/*.conf',
        f'{monitored_dir}/**/test-*.log',
    ]
    with open(config_file, 'w') as f:
        yaml.dump(config, f)

    # reload the config
    fact.kill('SIGHUP')
    sleep(0.1)
    return config, config_file


def test_extension_wildcard(wildcard_config, monitored_dir, server):
    process = Process.from_proc()

    # Should not match any pattern
    log_file = os.path.join(monitored_dir, 'app.log')
    with open(log_file, 'w') as f:
        f.write('This should be ignored')

    txt_file = os.path.join(monitored_dir, 'document.txt')
    with open(txt_file, 'w') as f:
        f.write('This should be captured')

    e = Event(process=process, event_type=EventType.CREATION,
              file=txt_file, host_path='')

    server.wait_events([e])


def test_prefix_wildcard(wildcard_config, monitored_dir, server):
    process = Process.from_proc()

    # Wrong prefix - should not match
    app_log = os.path.join(monitored_dir, 'app-test.log')
    with open(app_log, 'w') as f:
        f.write('This should be ignored')

    test_log = os.path.join(monitored_dir, 'test-app.log')
    with open(test_log, 'w') as f:
        f.write('This should be captured')

    e = Event(process=process, event_type=EventType.CREATION,
              file=test_log, host_path='')

    server.wait_events([e])


def test_recursive_wildcard(wildcard_config, monitored_dir, server):
    process = Process.from_proc()

    nested_dir = os.path.join(monitored_dir, 'level1', 'level2')
    os.makedirs(nested_dir, exist_ok=True)

    # Different extension - should not match
    nested_md = os.path.join(nested_dir, 'readme.md')
    with open(nested_md, 'w') as f:
        f.write('Should be ignored')

    root_txt = os.path.join(monitored_dir, 'root.txt')
    with open(root_txt, 'w') as f:
        f.write('Root level txt')

    nested_txt = os.path.join(nested_dir, 'nested.txt')
    with open(nested_txt, 'w') as f:
        f.write('Nested txt')

    events = [
        Event(process=process, event_type=EventType.CREATION,
              file=root_txt, host_path=''),
        Event(process=process, event_type=EventType.CREATION,
              file=nested_txt, host_path=''),
    ]

    server.wait_events(events)


def test_nonrecursive_wildcard(wildcard_config, monitored_dir, server):
    process = Process.from_proc()

    fut = os.path.join(monitored_dir, 'app.conf')
    with open(fut, 'w') as f:
        f.write('This should be captured')

    e = Event(process=process, event_type=EventType.CREATION,
              file=fut, host_path='')

    server.wait_events([e])


def test_multiple_patterns(wildcard_config, monitored_dir, server):
    process = Process.from_proc()

    # Matches no pattern
    conf_file = os.path.join(monitored_dir, 'config.yml')
    with open(conf_file, 'w') as f:
        f.write('Config file')

    txt_file = os.path.join(monitored_dir, 'notes.txt')
    with open(txt_file, 'w') as f:
        f.write('Text file')

    log_file = os.path.join(monitored_dir, 'test-output.log')
    with open(log_file, 'w') as f:
        f.write('Log file')

    events = [
        Event(process=process, event_type=EventType.CREATION,
              file=txt_file, host_path=''),
        Event(process=process, event_type=EventType.CREATION,
              file=log_file, host_path=''),
    ]

    server.wait_events(events)
