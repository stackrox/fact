import os
import shutil

import pytest

from event import Event, EventType, Process
from utils import get_metric_value


def get_inode_removed_count(fact_config):
    """
    Query Prometheus metrics to get the count of removed inodes.

    Args:
        fact_config: The fact configuration tuple (config dict, config file path).

    Returns:
        The current value of host_scanner_scan{label="InodeRemoved"} metric.
    """
    value = get_metric_value(fact_config, "host_scanner_scan", {"label": "InodeRemoved"})
    return int(value) if value is not None else 0


@pytest.mark.parametrize("dirname", [
    pytest.param('testdir', id='ASCII'),
    pytest.param('café', id='French'),
    pytest.param('файл', id='Cyrillic'),
    pytest.param('日本語', id='Japanese'),
])
def test_rmdir_empty(monitored_dir, server, fact_config, dirname):
    """
    Tests that removing an empty directory properly cleans up inode tracking.

    Scenario: File is removed first, leaving an empty directory, then rmdir is called.

    For now, directory deletion events are reported (like file unlink).
    Later, these events will be filtered out but inode cleanup will still happen.

    We use exact delta matching because:
    - Each test has an isolated monitored_dir
    - Periodic scans are disabled (scan_interval: 0)
    - No background activity should interfere

    Args:
        monitored_dir: Temporary directory path for creating the test directory.
        server: The server instance to communicate with.
        fact_config: The fact configuration.
        dirname: Directory name to test (including UTF-8 variants).
    """
    process = Process.from_proc()

    # Get baseline metric count
    initial_count = get_inode_removed_count(fact_config)

    # Create a directory
    test_dir = os.path.join(monitored_dir, dirname)
    os.mkdir(test_dir)

    # Create a file in it
    test_file = os.path.join(test_dir, 'file.txt')
    with open(test_file, 'w') as f:
        f.write('test content')

    # File creation should be tracked
    e1 = Event(process=process, event_type=EventType.CREATION,
              file=test_file, host_path=test_file)

    server.wait_events([e1])

    # Remove the file first, leaving an empty directory
    os.remove(test_file)

    # File deletion should be tracked
    e2 = Event(process=process, event_type=EventType.UNLINK,
              file=test_file, host_path=test_file)

    server.wait_events([e2])

    # Check that file deletion incremented the metric by exactly 1
    count_after_file = get_inode_removed_count(fact_config)
    file_delta = count_after_file - initial_count
    assert file_delta == 1, \
        f"Expected exactly 1 inode removed for file deletion, got {file_delta}"

    # Now remove the empty directory with rmdir
    os.rmdir(test_dir)

    # Directory deletion should be reported (TODO: this will be filtered out later)
    e3 = Event(process=process, event_type=EventType.UNLINK,
              file=test_dir, host_path=test_dir)

    server.wait_events([e3])

    # Check that directory deletion also incremented the metric by exactly 1
    final_count = get_inode_removed_count(fact_config)
    total_delta = final_count - initial_count
    assert total_delta == 2, \
        f"Expected exactly 2 inodes removed (1 file + 1 dir), got {total_delta}"


def test_rmdir_tree(monitored_dir, server, fact_config):
    """
    Tests that removing a directory tree recursively cleans up all inode tracking.

    Scenario: Directory with nested subdirectories and files is removed recursively
    using shutil.rmtree (similar to rm -rf).

    This tests that all inodes (both files and directories) are properly removed
    from tracking when a tree is deleted.

    Args:
        monitored_dir: Temporary directory path for creating test directories.
        server: The server instance to communicate with.
        fact_config: The fact configuration.
    """
    process = Process.from_proc()

    # Get baseline metric count
    initial_count = get_inode_removed_count(fact_config)

    # Create nested directories
    level1 = os.path.join(monitored_dir, 'level1')
    level2 = os.path.join(level1, 'level2')
    level3 = os.path.join(level2, 'level3')
    os.makedirs(level3)

    # Create files at different levels
    file1 = os.path.join(level1, 'file1.txt')
    file2 = os.path.join(level2, 'file2.txt')
    file3 = os.path.join(level3, 'file3.txt')

    with open(file1, 'w') as f:
        f.write('level1')
    with open(file2, 'w') as f:
        f.write('level2')
    with open(file3, 'w') as f:
        f.write('level3')

    # All files should be tracked
    creation_events = [
        Event(process=process, event_type=EventType.CREATION,
              file=file1, host_path=file1),
        Event(process=process, event_type=EventType.CREATION,
              file=file2, host_path=file2),
        Event(process=process, event_type=EventType.CREATION,
              file=file3, host_path=file3),
    ]

    server.wait_events(creation_events)

    # Remove the entire tree recursively (like rm -rf)
    # This will generate events for all files and directories
    # Order: deepest files/dirs first, then work up to the root
    shutil.rmtree(level1)

    # All deletions should be tracked: 3 files + 3 directories
    # shutil.rmtree deletes depth-first: file1, file2, file3, level3, level2, level1
    unlink_events = [
        Event(process=process, event_type=EventType.UNLINK,
              file=file1, host_path=file1),
        Event(process=process, event_type=EventType.UNLINK,
              file=file2, host_path=file2),
        Event(process=process, event_type=EventType.UNLINK,
              file=file3, host_path=file3),
        Event(process=process, event_type=EventType.UNLINK,
              file=level3, host_path=level3),
        Event(process=process, event_type=EventType.UNLINK,
              file=level2, host_path=level2),
        Event(process=process, event_type=EventType.UNLINK,
              file=level1, host_path=level1),
    ]

    server.wait_events(unlink_events)

    # Check that all inodes were removed: 3 files + 3 directories = 6 total
    final_count = get_inode_removed_count(fact_config)
    total_delta = final_count - initial_count
    assert total_delta == 6, \
        f"Expected exactly 6 inodes removed (3 files + 3 dirs), got {total_delta}"


def test_rmdir_ignored(monitored_dir, ignored_dir, server, fact_config):
    """
    Tests that directories removed outside monitored paths don't affect tracking.

    Verifies that inode_removed metric only increments for monitored paths.

    Args:
        monitored_dir: Temporary directory path that is monitored.
        ignored_dir: Temporary directory path that is not monitored.
        server: The server instance to communicate with.
        fact_config: The fact configuration.
    """
    process = Process.from_proc()

    # Get baseline metric count
    initial_count = get_inode_removed_count(fact_config)

    # Create directory in ignored path
    ignored_subdir = os.path.join(ignored_dir, 'ignored_subdir')
    os.mkdir(ignored_subdir)
    ignored_file = os.path.join(ignored_subdir, 'ignored.txt')
    with open(ignored_file, 'w') as f:
        f.write('ignored')

    # Remove ignored file and directory - should NOT generate events or increment metrics
    os.remove(ignored_file)
    os.rmdir(ignored_subdir)

    # Metric should not have changed
    count_after_ignored = get_inode_removed_count(fact_config)
    assert count_after_ignored == initial_count, \
        f"Ignored path operations should not increment inode_removed metric"

    # Create and remove directory in monitored path
    monitored_subdir = os.path.join(monitored_dir, 'monitored_subdir')
    os.mkdir(monitored_subdir)
    monitored_file = os.path.join(monitored_subdir, 'monitored.txt')
    with open(monitored_file, 'w') as f:
        f.write('monitored')

    # Monitored file creation should generate an event
    e1 = Event(process=process, event_type=EventType.CREATION,
              file=monitored_file, host_path=monitored_file)

    server.wait_events([e1])

    # Remove monitored file and directory
    os.remove(monitored_file)
    os.rmdir(monitored_subdir)

    # Both deletions should be tracked
    deletion_events = [
        Event(process=process, event_type=EventType.UNLINK,
              file=monitored_file, host_path=monitored_file),
        Event(process=process, event_type=EventType.UNLINK,
              file=monitored_subdir, host_path=monitored_subdir),
    ]

    server.wait_events(deletion_events)

    # Metric should have incremented by exactly 2 (file + dir)
    final_count = get_inode_removed_count(fact_config)
    total_delta = final_count - initial_count
    assert total_delta == 2, \
        f"Expected exactly 2 inodes removed from monitored path, got {total_delta}"


def test_rmdir_with_parent_inode(monitored_dir, server, fact_config):
    """
    Tests that directory deletion properly handles parent inode relationships.

    This is important because after deleting a subdirectory, the parent directory
    should still be tracked and able to track new files created in it.

    Args:
        monitored_dir: Temporary directory path for creating test directories.
        server: The server instance to communicate with.
        fact_config: The fact configuration.
    """
    process = Process.from_proc()

    # Get baseline metric count
    initial_count = get_inode_removed_count(fact_config)

    # Create a subdirectory
    subdir = os.path.join(monitored_dir, 'subdir')
    os.mkdir(subdir)

    # Create a file in the subdirectory
    test_file = os.path.join(subdir, 'test.txt')
    with open(test_file, 'w') as f:
        f.write('content')

    # Verify file creation is tracked
    e1 = Event(process=process, event_type=EventType.CREATION,
              file=test_file, host_path=test_file)
    server.wait_events([e1])

    # Create another file at the root level (parent directory)
    root_file = os.path.join(monitored_dir, 'root.txt')
    with open(root_file, 'w') as f:
        f.write('root content')

    e2 = Event(process=process, event_type=EventType.CREATION,
              file=root_file, host_path=root_file)
    server.wait_events([e2])

    # Remove the subdirectory and its contents
    os.remove(test_file)
    os.rmdir(subdir)

    # Verify deletions are tracked
    deletion_events = [
        Event(process=process, event_type=EventType.UNLINK,
              file=test_file, host_path=test_file),
        Event(process=process, event_type=EventType.UNLINK,
              file=subdir, host_path=subdir),
    ]
    server.wait_events(deletion_events)

    # Check metric incremented by 2 (file + subdir)
    count_after_subdir = get_inode_removed_count(fact_config)
    delta_after_subdir = count_after_subdir - initial_count
    assert delta_after_subdir == 2, \
        f"Expected 2 inodes removed (file + subdir), got {delta_after_subdir}"

    # Create a NEW file in the parent directory (monitored_dir)
    # This tests that removing the subdirectory didn't corrupt
    # the parent directory's inode tracking
    new_file = os.path.join(monitored_dir, 'new.txt')
    with open(new_file, 'w') as f:
        f.write('new content')

    e4 = Event(process=process, event_type=EventType.CREATION,
              file=new_file, host_path=new_file)
    server.wait_events([e4])

    # Remove the new file to clean up
    os.remove(new_file)

    e5 = Event(process=process, event_type=EventType.UNLINK,
              file=new_file, host_path=new_file)
    server.wait_events([e5])

    # Final metric check: should be 3 total (test_file, subdir, new_file)
    final_count = get_inode_removed_count(fact_config)
    total_delta = final_count - initial_count
    assert total_delta == 3, \
        f"Expected 3 inodes removed total, got {total_delta}"
