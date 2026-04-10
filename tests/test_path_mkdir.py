import os

import pytest

from event import Event, EventType, Process


@pytest.mark.parametrize("dirname", [
    pytest.param('level3', id='ASCII'),
    pytest.param('café', id='French'),
    pytest.param('файл', id='Cyrillic'),
    pytest.param('日本語', id='Japanese'),
])
def test_mkdir_nested(monitored_dir, server, dirname):
    """
    Tests that creating nested directories tracks all inodes correctly.

    Args:
        monitored_dir: Temporary directory path for creating the test directory.
        server: The server instance to communicate with.
        dirname: Final directory name to test (including UTF-8 variants).
    """
    process = Process.from_proc()

    # Create nested directories
    test_dir = os.path.join(monitored_dir, 'level1', 'level2', dirname)
    os.makedirs(test_dir, exist_ok=True)

    # Create a file in the deepest directory
    test_file = os.path.join(test_dir, 'deep_file.txt')
    with open(test_file, 'w') as f:
        f.write('nested content')

    # Directory creation events are tracked internally but not sent to sensor
    # Only the file creation event should be sent
    events = [
        Event(process=process, event_type=EventType.CREATION,
              file=test_file, host_path=test_file),
    ]

    server.wait_events(events)


def test_mkdir_ignored(monitored_dir, ignored_dir, server):
    """
    Tests that directories created outside monitored paths are ignored.

    Args:
        monitored_dir: Temporary directory path that is monitored.
        ignored_dir: Temporary directory path that is not monitored.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()

    # Create directory in ignored path - should not be tracked
    ignored_subdir = os.path.join(ignored_dir, 'ignored_subdir')
    os.mkdir(ignored_subdir)
    ignored_file = os.path.join(ignored_subdir, 'ignored.txt')
    with open(ignored_file, 'w') as f:
        f.write('ignored')

    # Create directory in monitored path - should be tracked
    monitored_subdir = os.path.join(monitored_dir, 'monitored_subdir')
    os.mkdir(monitored_subdir)
    monitored_file = os.path.join(monitored_subdir, 'monitored.txt')
    with open(monitored_file, 'w') as f:
        f.write('monitored')

    # Only the monitored file should generate an event (directories are tracked internally)
    e = Event(process=process, event_type=EventType.CREATION,
              file=monitored_file, host_path=monitored_file)

    server.wait_events([e])
