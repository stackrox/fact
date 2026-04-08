import os

import pytest

from utils import join_path_with_filename, path_to_string
from event import Event, EventType, Process


@pytest.mark.parametrize("filename", [
    pytest.param('rename.txt', id='ASCII'),
    pytest.param('café.txt', id='French'),
    pytest.param('файл.txt', id='Cyrillic'),
    pytest.param('测试.txt', id='Chinese'),
    pytest.param('🚀rocket.txt', id='Emoji'),
    pytest.param(b'test\xff\xfe.txt', id='Invalid'),
])
def test_rename(monitored_dir, server, filename):
    """
    Tests the renaming of a file and verifies that the corresponding
    events are captured by the server.

    Args:
        monitored_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
        filename: Name of the target path to rename to.
    """
    # File Under Test
    fut = join_path_with_filename(monitored_dir, filename)
    old_fut = os.path.join(monitored_dir, 'file.txt')

    with open(old_fut, 'w') as f:
        f.write('This is a test')
    os.rename(old_fut, fut)
    os.rename(fut, old_fut)

    # Convert fut to string for the Event, replacing invalid UTF-8 with U+FFFD
    fut = path_to_string(fut)

    p = Process.from_proc()
    server.wait_events([
        Event(process=p, event_type=EventType.CREATION,
              file=old_fut, host_path=old_fut),
        Event(process=p, event_type=EventType.RENAME, file=fut,
              host_path=fut, old_file=old_fut, old_host_path=old_fut),
        Event(process=p, event_type=EventType.RENAME, file=old_fut,
              host_path=old_fut, old_file=fut, old_host_path=fut),
    ])


def test_ignored(monitored_dir, ignored_dir, server):
    """
    Tests that rename events on ignored files are not captured by the
    server.

    Args:
        monitored_dir: Temporary directory path for creating the test file.
        ignored_dir: Temporary directory path that is not monitored by fact.
        server: The server instance to communicate with.
    """
    ignored_path = os.path.join(ignored_dir, 'test.txt')
    p = Process.from_proc()

    with open(ignored_path, 'w') as f:
        f.write('This is to be ignored')
    new_ignored_path = os.path.join(ignored_dir, 'rename.txt')

    # Renaming in between ignored paths should not generate events
    os.rename(ignored_path, new_ignored_path)

    # Renaming to a monitored path requires a scan, we need to wait for
    # it before we can continue modifying the FS
    new_path = os.path.join(monitored_dir, 'rename.txt')
    os.rename(new_ignored_path, new_path)
    server.wait_events([
        Event(process=p, event_type=EventType.RENAME,
              file=new_path, host_path=new_path, old_file=new_ignored_path, old_host_path=''),
    ])

    # Renaming from a monitored path generates an event too
    os.rename(new_path, ignored_path)

    server.wait_events([
        Event(process=p, event_type=EventType.RENAME,
              file=ignored_path, host_path='', old_file=new_path, old_host_path=new_path),
    ])


def test_rename_dir(monitored_dir, ignored_dir, server):
    """
    Test renaming a directory is caught

    We start by creating a subdirectory in an ignored path and give it a
    few files to test we only get events for the directory itself. We
    then check renaming within the ignored path doesn't trigger events,
    move the subdirectory to a monitored path, renaming it within that
    path and moving it back out, these three interactions should
    generate events for the directory only.

    Args:
        monitored_dir: Temporary directory path for creating the test file.
        ignored_dir: Temporary directory path that is not monitored by fact.
        server: The server instance to communicate with.
    """
    # Directory Under Test
    dut = os.path.join(monitored_dir, 'some-dir')
    new_dut = os.path.join(monitored_dir, 'other-dir')
    ignored_dut = os.path.join(ignored_dir, 'some-dir')
    new_ignored_dut = os.path.join(ignored_dir, 'other-dir')

    os.mkdir(ignored_dut)
    for i in range(3):
        with open(os.path.join(ignored_dut, f'{i}.txt'), 'w') as f:
            f.write('This is a test')

    # This rename should generate no events
    os.rename(ignored_dut, new_ignored_dut)

    # Going from a non-monitored directory to a monitored one requires a scan of
    # the filesystem to add any subdirectories and files, so we need to wait for
    # it to end before we can continue modifying the FS.
    os.rename(new_ignored_dut, dut)

    p = Process.from_proc()
    server.wait_events([
        Event(process=p, event_type=EventType.RENAME, file=dut,
              host_path=dut, old_file=new_ignored_dut, old_host_path=''),
    ])

    # The following two event should produce full events without scanning the FS.
    os.rename(dut, new_dut)
    os.rename(new_dut, ignored_dut)

    events = [
        Event(process=p, event_type=EventType.RENAME,
              file=new_dut, host_path=new_dut, old_file=dut, old_host_path=dut),
        Event(process=p, event_type=EventType.RENAME,
              file=ignored_dut, host_path='', old_file=new_dut, old_host_path=new_dut),
    ]

    server.wait_events(events)


def test_overlay(test_container, server):
    # File Under Test
    fut = '/container-dir/test.txt'
    new_fut = '/container-dir/rename.txt'

    # Create the exec and an equivalent event that it will trigger
    test_container.exec_run(f'touch {fut}')
    test_container.exec_run(f'mv {fut} {new_fut}')

    touch = Process.in_container(
        exe_path='/usr/bin/touch',
        args=f'touch {fut}',
        name='touch',
        container_id=test_container.id[:12],
    )
    mv = Process.in_container(
        exe_path='/usr/bin/mv',
        args=f'mv {fut} {new_fut}',
        name='mv',
        container_id=test_container.id[:12],
    )
    events = [
        Event(process=touch, event_type=EventType.CREATION,
              file=fut, host_path=''),
        Event(process=mv, event_type=EventType.RENAME,
              file=new_fut, host_path='', old_file=fut, old_host_path=''),
    ]

    server.wait_events(events)


def test_mounted_dir(test_container, ignored_dir, server):
    # File Under Test
    fut = '/mounted/test.txt'
    new_fut = '/mounted/rename.txt'

    # Create the exec and an equivalent event that it will trigger
    test_container.exec_run(f'touch {fut}')
    test_container.exec_run(f'mv {fut} {new_fut}')

    touch = Process.in_container(
        exe_path='/usr/bin/touch',
        args=f'touch {fut}',
        name='touch',
        container_id=test_container.id[:12],
    )
    mv = Process.in_container(
        exe_path='/usr/bin/mv',
        args=f'mv {fut} {new_fut}',
        name='mv',
        container_id=test_container.id[:12],
    )
    # ignored_dir is not monitored, so host_path should be blank
    events = [
        Event(process=touch, event_type=EventType.CREATION,
              file=fut, host_path=''),
        Event(process=mv, event_type=EventType.RENAME,
              file=new_fut, host_path='', old_file=fut, old_host_path=''),
    ]

    server.wait_events(events)
