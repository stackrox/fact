import os
import re
import subprocess

import docker.models.containers
import pytest

from event import Event, EventType, Process
from server import EventServer
from utils import join_path_with_filename, path_to_string


def setup_symlink(file: str | bytes, link: str | bytes) -> list[Event]:
    with open(file, 'w') as f:
        f.write('This is a test')

    os.symlink(file, link)

    file = path_to_string(file)
    link = path_to_string(link)
    proc = Process.from_proc()

    return [
        Event(
            process=proc,
            event_type=EventType.CREATION,
            file=file,
            host_path=file,
        ),
        Event(
            process=proc,
            event_type=EventType.OPEN,
            file=link,
            host_path=link,
        ),
    ]


def overwrite_symlink(file: str, link: str) -> list[Event]:
    """
    Overwrite the provided link with file.

    Returns:
        A list of expected events.
    """
    # Overwrite the symbolic link with ln -sf
    subprocess.run(['ln', '-s', '-f', file, link], check=True)

    proc = Process.from_proc()

    # Build the ln process from the self proc.
    proc.exe_path = '/usr/bin/ln'
    proc.args = f'ln -s -f {file} {link}'
    proc.pid = None
    proc.name = 'ln'

    # Sometimes the symlink is moved too fast and we can't read the
    # inode in userspace, so the pattern here checks for the actual path
    # or an empty string
    parent_dir = os.path.dirname(link)
    new_link_pattern = rf'{parent_dir}/[0-9a-zA-Z]{{8}}'
    new_link = re.compile(new_link_pattern)
    return [
        Event(
            process=proc,
            event_type=EventType.OPEN,
            file=new_link,
            host_path=link,
        ),
        Event(
            process=proc,
            event_type=EventType.RENAME,
            file=link,
            host_path='',
            old_file=new_link,
            old_host_path=link,
        ),
    ]


@pytest.mark.parametrize(
    ('filename', 'symlink'),
    [
        pytest.param('target.txt', 'symlink.txt', id='ASCII'),
        pytest.param('café.txt', 'éfac.txt', id='French'),
        pytest.param('файл.txt', 'лйаф.txt', id='Cyrillic'),
        pytest.param('测试.txt', '试测.txt', id='Chinese'),
        pytest.param('🚀rocket.txt', 'rocket🚀.txt', id='Emoji'),
        pytest.param(b'test\xff\xfe.txt', '\xff\xfetest.txt', id='Invalid'),
    ],
)
def test_create_symlink(
    monitored_dir: str,
    server: EventServer,
    filename: str | bytes,
    symlink: str | bytes,
):
    """
    Test creating symlinks in a monitored directory is properly captured.

    Args:
        monitored_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
        filename: Name of the file to create (includes UTF-8 test cases).
    """
    file = join_path_with_filename(monitored_dir, filename)
    link = join_path_with_filename(monitored_dir, symlink)

    server.wait_events(setup_symlink(file, link))


def test_follow_symlink_to_file(
    monitored_dir: str, ignored_dir: str, server: EventServer
):
    """
    Creating a symlink to a file that is not monitored should start
    monitoring it.
    """
    file = os.path.join(ignored_dir, 'file.txt')
    link = os.path.join(monitored_dir, 'symlink')
    proc = Process.from_proc()

    with open(file, 'w') as f:
        f.write('This is a test')
    os.symlink(file, link)

    server.wait_events(
        [
            Event(
                process=proc,
                event_type=EventType.OPEN,
                file=link,
                host_path=link,
            )
        ]
    )

    # At this point, modifying the file in the ignored path should
    # trigger events
    with open(file, 'w') as f:
        f.write('This is a test')

    server.wait_events(
        [
            Event(
                process=proc,
                event_type=EventType.OPEN,
                file=file,
                host_path=link,
            ),
        ]
    )


def test_follow_symlink_to_file_relative(
    monitored_dir: str, ignored_dir: str, server: EventServer
):
    """
    Creating a symlink to a file that is not monitored should start
    monitoring it.
    """
    file = os.path.join(ignored_dir, 'file.txt')
    link = os.path.join(monitored_dir, 'symlink')
    target = os.path.join('..', os.path.basename(ignored_dir), 'file.txt')
    proc = Process.from_proc()

    with open(file, 'w') as f:
        f.write('This is a test')
    os.symlink(target, link)

    server.wait_events(
        [
            Event(
                process=proc,
                event_type=EventType.OPEN,
                file=link,
                host_path=link,
            )
        ]
    )

    # At this point, modifying the file in the ignored path should
    # trigger events
    with open(file, 'w') as f:
        f.write('This is a test')

    server.wait_events(
        [
            Event(
                process=proc,
                event_type=EventType.OPEN,
                file=file,
                host_path=link,
            ),
        ]
    )


@pytest.mark.skip(
    reason='symlinks with absolute paths are broken when '
    + 'running inside container'
)
def test_follow_symlink_to_dir(
    monitored_dir: str, ignored_dir: str, server: EventServer
):
    """
    Creating a symlink to a directory that is not monitored should start
    monitoring it.
    """
    file = os.path.join(ignored_dir, 'file.txt')
    other_file = os.path.join(ignored_dir, 'other.txt')
    link = os.path.join(monitored_dir, 'symlink')
    proc = Process.from_proc()

    with open(file, 'w') as f:
        f.write('This is a test')
    os.symlink(ignored_dir, link)

    server.wait_events(
        [
            Event(
                process=proc,
                event_type=EventType.OPEN,
                file=link,
                host_path=link,
            )
        ]
    )

    # At this point, modifying files in the ignored path should
    # trigger events
    with open(file, 'w') as f:
        f.write('This is a test')
    with open(other_file, 'w') as f:
        f.write('This is a test')

    server.wait_events(
        [
            Event(
                process=proc,
                event_type=EventType.OPEN,
                file=file,
                host_path=link,
            ),
            Event(
                process=proc,
                event_type=EventType.CREATION,
                file=other_file,
                host_path=link,
            ),
        ]
    )


def test_follow_symlink_to_dir_relative(
    monitored_dir: str, ignored_dir: str, server: EventServer
):
    """
    Creating a symlink to a directory that is not monitored should start
    monitoring it.
    """
    file = os.path.join(ignored_dir, 'file.txt')
    other_file = os.path.join(ignored_dir, 'other.txt')
    link = os.path.join(monitored_dir, 'symlink')
    link_file = os.path.join(link, 'file.txt')
    link_other = os.path.join(link, 'other.txt')
    target = os.path.join('..', os.path.basename(ignored_dir))
    proc = Process.from_proc()

    with open(file, 'w') as f:
        f.write('This is a test')
    os.symlink(target, link)

    server.wait_events(
        [
            Event(
                process=proc,
                event_type=EventType.OPEN,
                file=link,
                host_path=link,
            )
        ]
    )

    # At this point, modifying files in the ignored path should
    # trigger events
    with open(file, 'w') as f:
        f.write('This is a test')
    with open(other_file, 'w') as f:
        f.write('This is a test')

    server.wait_events(
        [
            Event(
                process=proc,
                event_type=EventType.OPEN,
                file=file,
                host_path=link_file,
            ),
            Event(
                process=proc,
                event_type=EventType.CREATION,
                file=other_file,
                host_path=link_other,
            ),
        ]
    )


def test_overwrite_symlink(monitored_dir: str, server: EventServer):
    """
    Test overwriting a symlink in a monitored directory is properly captured.

    Args:
        monitored_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
    """
    file = os.path.join(monitored_dir, 'file.txt')
    link = os.path.join(monitored_dir, 'symlink')

    events = setup_symlink(file, link)
    events.extend(overwrite_symlink(file, link))

    server.wait_events(events)


def test_multiple(monitored_dir: str, server: EventServer):
    """
    Tests creating multiple symlinks is properly captured

    Args:
        monitored_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
    """
    proc = Process.from_proc()
    file = os.path.join(monitored_dir, 'file.txt')
    with open(file, 'w') as f:
        f.write('This is a test')
    events = [
        Event(
            process=proc,
            file=file,
            host_path=file,
            event_type=EventType.CREATION,
        )
    ]

    for i in range(3):
        link = os.path.join(monitored_dir, f'symlink{i}')
        os.symlink(file, link)

        events.append(
            Event(
                process=proc,
                file=link,
                host_path=link,
                event_type=EventType.OPEN,
            )
        )

    server.wait_events(events)


def test_multiple_overwrite(monitored_dir: str, server: EventServer):
    """
    Tests creating multiple symlinks is properly captured

    Args:
        monitored_dir: Temporary directory path for creating the test file.
        server: The server instance to communicate with.
    """
    proc = Process.from_proc()
    file = os.path.join(monitored_dir, 'file.txt')
    with open(file, 'w') as f:
        f.write('This is a test')
    events = [
        Event(
            process=proc,
            file=file,
            host_path=file,
            event_type=EventType.CREATION,
        )
    ]

    for i in range(3):
        link = os.path.join(monitored_dir, f'symlink{i}')
        os.symlink(file, link)

        events.append(
            Event(
                process=proc,
                file=link,
                host_path=link,
                event_type=EventType.OPEN,
            )
        )

        events.extend(overwrite_symlink(file, link))

    server.wait_events(events)


def test_ignored(monitored_dir: str, ignored_dir: str, server: EventServer):
    """
    Tests that symlink events on ignored file are not captured.

    Args:
        monitored_dir: Temporary directory path for creating the test file.
        ignored_dir: Temporary directory path that is not monitored by fact.
        server: The server instance to communicate with.
    """
    file = os.path.join(ignored_dir, 'test.txt')
    ignored_link = os.path.join(ignored_dir, 'ignored')
    monitored_link = os.path.join(monitored_dir, 'symlink')

    os.symlink(file, ignored_link)
    os.symlink(file, monitored_link)

    server.wait_events(
        [
            Event(
                process=Process.from_proc(),
                event_type=EventType.OPEN,
                file=monitored_link,
                host_path=monitored_link,
            )
        ]
    )


def test_ovfs(
    test_container: docker.models.containers.Container, server: EventServer
):
    assert test_container.id is not None
    container_id = test_container.id[:12]
    file = '/container-dir/test.txt'
    link = '/container-dir/symlink'

    res = test_container.exec_run(f'touch {file}')
    assert res.exit_code == 0
    res = test_container.exec_run(f'ln -s {file} {link}')
    assert res.exit_code == 0

    touch = Process.in_container(
        exe_path='/usr/bin/touch',
        args=f'touch {file}',
        name='touch',
        container_id=container_id,
    )
    ln = Process.in_container(
        exe_path='/usr/bin/ln',
        args=f'ln -s {file} {link}',
        name='ln',
        container_id=container_id,
    )

    server.wait_events(
        [
            Event(
                process=touch,
                event_type=EventType.CREATION,
                file=file,
                host_path='',
            ),
            Event(
                process=ln,
                event_type=EventType.OPEN,
                file=link,
                host_path='',
            ),
        ]
    )


def test_mounted_dir(
    test_container: docker.models.containers.Container,
    ignored_dir: str,
    server: EventServer,
):
    assert test_container.id is not None
    container_id = test_container.id[:12]
    file = '/mounted/test.txt'
    link = '/mounted/symlink'

    test_container.exec_run(f'touch {file}')
    test_container.exec_run(f'ln -s {file} {link}')

    touch = Process.in_container(
        exe_path='/usr/bin/touch',
        args=f'touch {file}',
        name='touch',
        container_id=container_id,
    )
    ln = Process.in_container(
        exe_path='/usr/bin/ln',
        args=f'ln -s {file} {link}',
        name='ln',
        container_id=container_id,
    )

    # ignored_dir is not monitored, so host_path should be blank
    server.wait_events(
        [
            Event(
                process=touch,
                event_type=EventType.CREATION,
                file=file,
                host_path='',
            ),
            Event(
                process=ln,
                event_type=EventType.OPEN,
                file=link,
                host_path='',
            ),
        ]
    )
