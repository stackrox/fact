import os

import pytest

from event import Event, EventType, Process


def test_mkdir_nested(monitored_dir, server):
    """
    Tests that creating nested directories tracks all inodes correctly.

    Args:
        monitored_dir: Temporary directory path for creating the test directory.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()

    # Create nested directories
    level1 = os.path.join(monitored_dir, 'level1')
    level2 = os.path.join(level1, 'level2')
    level3 = os.path.join(level2, 'level3')

    os.mkdir(level1)
    os.mkdir(level2)
    os.mkdir(level3)

    # Create a file in the deepest directory
    test_file = os.path.join(level3, 'deep_file.txt')
    with open(test_file, 'w') as f:
        f.write('nested content')

    events = [
        Event(process=process, event_type=EventType.CREATION,
              file=level1, host_path=level1),
        Event(process=process, event_type=EventType.CREATION,
              file=level2, host_path=level2),
        Event(process=process, event_type=EventType.CREATION,
              file=level3, host_path=level3),
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

    # Create directory in monitored path - should be tracked
    monitored_subdir = os.path.join(monitored_dir, 'monitored_subdir')
    os.mkdir(monitored_subdir)

    # Only the monitored directory should generate an event
    e = Event(process=process, event_type=EventType.CREATION,
              file=monitored_subdir, host_path=monitored_subdir)

    server.wait_events([e])
