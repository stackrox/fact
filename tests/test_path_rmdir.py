from __future__ import annotations

import os
import shutil
import sys

import pytest

from event import Event, EventType, Process
from server import EventServer


@pytest.mark.parametrize(
    'dirname',
    [
        pytest.param('testdir', id='ASCII'),
        pytest.param('café', id='French'),
        pytest.param('файл', id='Cyrillic'),
        pytest.param('日本語', id='Japanese'),
    ],
)
def test_rmdir_empty(
    monitored_dir: str,
    server: EventServer,
    dirname: str,
):
    """
    Tests file events on both outputs and the rmdir event on OTLP.

    Args:
        monitored_dir: Temporary directory path for creating the test directory.
        server: The event server.
        dirname: Directory name to test, including UTF-8 variants.
    """
    process = Process.from_proc()
    test_dir = os.path.join(monitored_dir, dirname)
    os.mkdir(test_dir)
    test_file = os.path.join(test_dir, 'file.txt')
    with open(test_file, 'w') as f:
        f.write('test content')

    events = []
    if server.output_mode == 'otlp':
        events = [
            Event(
                process=process,
                event_type=EventType.MKDIR,
                file=test_dir,
                host_path=test_dir,
            ),
        ]
    events.append(
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=test_file,
            host_path=test_file,
        )
    )
    server.wait_events(events)

    os.remove(test_file)
    server.wait_events(
        [
            Event(
                process=process,
                event_type=EventType.UNLINK,
                file=test_file,
                host_path=test_file,
            )
        ]
    )

    os.rmdir(test_dir)
    if server.output_mode == 'otlp':
        server.wait_events(
            [
                Event(
                    process=process,
                    event_type=EventType.RMDIR,
                    file=test_dir,
                    host_path=test_dir,
                )
            ]
        )


@pytest.mark.skipif(
    sys.version_info < (3, 10),
    reason='shutil.rmtree behavior changes between interpreter versions',
)
def test_rmdir_recursive(
    monitored_dir: str,
    server: EventServer,
):
    """
    Tests that recursive deletion emits unlink events and OTLP rmdir events.

    Args:
        monitored_dir: Temporary directory path for creating test directories.
        server: The event server.
    """
    process = Process.from_proc()
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

    events = []
    if server.output_mode == 'otlp':
        events = [
            Event(
                process=process,
                event_type=EventType.MKDIR,
                file=level1,
                host_path=level1,
            ),
            Event(
                process=process,
                event_type=EventType.MKDIR,
                file=level2,
                host_path=level2,
            ),
            Event(
                process=process,
                event_type=EventType.MKDIR,
                file=level3,
                host_path=level3,
            ),
        ]

    events.extend(
        [
            Event(
                process=process,
                event_type=EventType.CREATION,
                file=file1,
                host_path=file1,
            ),
            Event(
                process=process,
                event_type=EventType.CREATION,
                file=file2,
                host_path=file2,
            ),
            Event(
                process=process,
                event_type=EventType.CREATION,
                file=file3,
                host_path=file3,
            ),
        ]
    )

    server.wait_events(events)

    shutil.rmtree(level1)

    events = [
        Event(
            process=process,
            event_type=EventType.UNLINK,
            file=file1,
            host_path=file1,
        ),
        Event(
            process=process,
            event_type=EventType.UNLINK,
            file=file2,
            host_path=file2,
        ),
        Event(
            process=process,
            event_type=EventType.UNLINK,
            file=file3,
            host_path=file3,
        ),
    ]
    if server.output_mode == 'otlp':
        events.extend(
            [
                Event(
                    process=process,
                    event_type=EventType.RMDIR,
                    file=level1,
                    host_path=level1,
                ),
                Event(
                    process=process,
                    event_type=EventType.RMDIR,
                    file=level2,
                    host_path=level2,
                ),
                Event(
                    process=process,
                    event_type=EventType.RMDIR,
                    file=level3,
                    host_path=level3,
                ),
            ]
        )
    server.wait_events(events, ordered=False)


def test_rmdir_ignored(
    monitored_dir: str,
    ignored_dir: str,
    server: EventServer,
):
    """
    Tests that only operations in monitored directories emit events.

    Args:
        monitored_dir: Temporary directory path that is monitored.
        ignored_dir: Temporary directory path that is not monitored.
        server: The event server.
    """
    process = Process.from_proc()

    ignored_subdir = os.path.join(ignored_dir, 'ignored_subdir')
    os.mkdir(ignored_subdir)
    ignored_file = os.path.join(ignored_subdir, 'ignored.txt')
    with open(ignored_file, 'w') as f:
        f.write('ignored')

    os.remove(ignored_file)
    os.rmdir(ignored_subdir)

    monitored_subdir = os.path.join(monitored_dir, 'monitored_subdir')
    os.mkdir(monitored_subdir)
    monitored_file = os.path.join(monitored_subdir, 'monitored.txt')
    with open(monitored_file, 'w') as f:
        f.write('monitored')

    events = []
    if server.output_mode == 'otlp':
        events = [
            Event(
                process=process,
                event_type=EventType.MKDIR,
                file=monitored_subdir,
                host_path=monitored_subdir,
            ),
        ]
    events.append(
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=monitored_file,
            host_path=monitored_file,
        )
    )
    server.wait_events(events)

    os.remove(monitored_file)
    os.rmdir(monitored_subdir)

    events = [
        Event(
            process=process,
            event_type=EventType.UNLINK,
            file=monitored_file,
            host_path=monitored_file,
        )
    ]
    if server.output_mode == 'otlp':
        events.append(
            Event(
                process=process,
                event_type=EventType.RMDIR,
                file=monitored_subdir,
                host_path=monitored_subdir,
            )
        )
    server.wait_events(events)


def test_rmdir_with_parent_inode(
    monitored_dir: str,
    server: EventServer,
):
    """
    Tests that directory deletion properly handles parent inode relationships.

    This is important because after deleting a subdirectory, the parent
    directory should still be tracked and able to track new files created in it.

    Args:
        monitored_dir: Temporary directory path for creating test directories.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()

    # Create a subdirectory
    subdir = os.path.join(monitored_dir, 'subdir')
    os.mkdir(subdir)

    # Create a file in the subdirectory
    test_file = os.path.join(subdir, 'test.txt')
    with open(test_file, 'w') as f:
        f.write('content')

    # Verify file creation is tracked
    events = []
    if server.output_mode == 'otlp':
        events.append(
            Event(
                process=process,
                event_type=EventType.MKDIR,
                file=subdir,
                host_path=subdir,
            ),
        )
    events.append(
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=test_file,
            host_path=test_file,
        )
    )
    server.wait_events(events)

    # Create another file at the root level (parent directory)
    root_file = os.path.join(monitored_dir, 'root.txt')
    with open(root_file, 'w') as f:
        f.write('root content')

    server.wait_event(
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=root_file,
            host_path=root_file,
        )
    )

    # Remove the subdirectory and its contents
    os.remove(test_file)
    os.rmdir(subdir)

    # Verify file deletion is tracked
    events = [
        Event(
            process=process,
            event_type=EventType.UNLINK,
            file=test_file,
            host_path=test_file,
        )
    ]
    if server.output_mode == 'otlp':
        events.append(
            Event(
                process=process,
                event_type=EventType.RMDIR,
                file=subdir,
                host_path=subdir,
            )
        )
    server.wait_events(events)

    # Create a NEW file in the parent directory (monitored_dir)
    # This tests that removing the subdirectory didn't corrupt
    # the parent directory's inode tracking
    new_file = os.path.join(monitored_dir, 'new.txt')
    with open(new_file, 'w') as f:
        f.write('new content')

    server.wait_event(
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=new_file,
            host_path=new_file,
        )
    )

    # Remove the new file to clean up
    os.remove(new_file)

    server.wait_event(
        Event(
            process=process,
            event_type=EventType.UNLINK,
            file=new_file,
            host_path=new_file,
        )
    )
