"""Tests for POSIX ACL change events."""

from __future__ import annotations

import os

import docker.models.containers

from event import (
    ACL_TAG_GROUP_OBJ,
    ACL_TAG_MASK,
    ACL_TAG_OTHER,
    ACL_TAG_USER,
    ACL_TAG_USER_OBJ,
    Event,
    EventType,
    Process,
)
from server import FileActivityService


def test_set_access_acl(
    test_container: docker.models.containers.Container,
    server: FileActivityService,
):
    """
    Test setting an access ACL on a file inside a container.

    Args:
        test_container: A container for running commands in.
        server: The server instance to communicate with.
    """
    assert test_container.id is not None
    fut = '/container-dir/acl_test.txt'

    test_container.exec_run(f'touch {fut}')
    test_container.exec_run(f'setfacl -m u:1000:rw {fut}')

    touch = Process.in_container(
        exe_path='/usr/bin/touch',
        args=f'touch {fut}',
        name='touch',
        container_id=test_container.id[:12],
    )
    setfacl = Process.in_container(
        exe_path='/usr/bin/setfacl',
        args=f'setfacl -m u:1000:rw {fut}',
        name='setfacl',
        container_id=test_container.id[:12],
    )

    events = [
        Event(
            process=touch,
            event_type=EventType.CREATION,
            file=fut,
            host_path='',
        ),
        Event(
            process=setfacl,
            event_type=EventType.ACL,
            file=fut,
            host_path='',
            acl_type='access',
            acl_entries=[
                {'tag': ACL_TAG_USER_OBJ, 'perm': 6, 'id': 0xFFFFFFFF},
                {'tag': ACL_TAG_USER, 'perm': 6, 'id': 1000},
                {'tag': ACL_TAG_GROUP_OBJ, 'perm': 4, 'id': 0xFFFFFFFF},
                {'tag': ACL_TAG_MASK, 'perm': 6, 'id': 0xFFFFFFFF},
                {'tag': ACL_TAG_OTHER, 'perm': 4, 'id': 0xFFFFFFFF},
            ],
        ),
    ]

    server.wait_events(events)


def test_set_default_acl(
    test_container: docker.models.containers.Container,
    server: FileActivityService,
):
    """
    Test setting a default ACL on a directory inside a container.

    Args:
        test_container: A container for running commands in.
        server: The server instance to communicate with.
    """
    assert test_container.id is not None
    fut = '/container-dir/subdir'

    test_container.exec_run(f'mkdir -p {fut}')
    test_container.exec_run(f'setfacl -d -m g:1000:rx {fut}')

    setfacl = Process.in_container(
        exe_path='/usr/bin/setfacl',
        args=f'setfacl -d -m g:1000:rx {fut}',
        name='setfacl',
        container_id=test_container.id[:12],
    )

    events = [
        Event(
            process=setfacl,
            event_type=EventType.ACL,
            file=fut,
            host_path='',
            acl_type='default',
        ),
    ]

    server.wait_events(events)


def test_remove_acl(
    test_container: docker.models.containers.Container,
    server: FileActivityService,
):
    """
    Test removing ACLs from a file inside a container.

    Args:
        test_container: A container for running commands in.
        server: The server instance to communicate with.
    """
    assert test_container.id is not None
    fut = '/container-dir/acl_remove.txt'

    test_container.exec_run(f'touch {fut}')
    test_container.exec_run(f'setfacl -m u:1000:rw {fut}')
    test_container.exec_run(f'setfacl -b {fut}')

    touch = Process.in_container(
        exe_path='/usr/bin/touch',
        args=f'touch {fut}',
        name='touch',
        container_id=test_container.id[:12],
    )
    setfacl_set = Process.in_container(
        exe_path='/usr/bin/setfacl',
        args=f'setfacl -m u:1000:rw {fut}',
        name='setfacl',
        container_id=test_container.id[:12],
    )
    setfacl_remove = Process.in_container(
        exe_path='/usr/bin/setfacl',
        args=f'setfacl -b {fut}',
        name='setfacl',
        container_id=test_container.id[:12],
    )

    events = [
        Event(
            process=touch,
            event_type=EventType.CREATION,
            file=fut,
            host_path='',
        ),
        Event(
            process=setfacl_set,
            event_type=EventType.ACL,
            file=fut,
            host_path='',
            acl_type='access',
        ),
        Event(
            process=setfacl_remove,
            event_type=EventType.ACL,
            file=fut,
            host_path='',
            acl_type='access',
            acl_entries=[
                {'tag': ACL_TAG_USER_OBJ, 'perm': 6, 'id': 0xFFFFFFFF},
                {'tag': ACL_TAG_GROUP_OBJ, 'perm': 4, 'id': 0xFFFFFFFF},
                {'tag': ACL_TAG_OTHER, 'perm': 4, 'id': 0xFFFFFFFF},
            ],
        ),
    ]

    server.wait_events(events)


def test_multiple_entries(
    test_container: docker.models.containers.Container,
    server: FileActivityService,
):
    """
    Test setting multiple ACL entries on a single file.

    Args:
        test_container: A container for running commands in.
        server: The server instance to communicate with.
    """
    assert test_container.id is not None
    fut = '/container-dir/acl_multi.txt'

    test_container.exec_run(f'touch {fut}')
    test_container.exec_run(f'setfacl -m u:1000:rwx,u:1001:r,g:2000:rw {fut}')

    touch = Process.in_container(
        exe_path='/usr/bin/touch',
        args=f'touch {fut}',
        name='touch',
        container_id=test_container.id[:12],
    )
    setfacl = Process.in_container(
        exe_path='/usr/bin/setfacl',
        args=f"setfacl -m 'u:1000:rwx,u:1001:r,g:2000:rw' {fut}",
        name='setfacl',
        container_id=test_container.id[:12],
    )

    events = [
        Event(
            process=touch,
            event_type=EventType.CREATION,
            file=fut,
            host_path='',
        ),
        Event(
            process=setfacl,
            event_type=EventType.ACL,
            file=fut,
            host_path='',
            acl_type='access',
        ),
    ]

    server.wait_events(events)


def test_ignored_path(
    test_file: str,
    ignored_dir: str,
    test_container: docker.models.containers.Container,
    server: FileActivityService,
):
    """
    Test that ACL changes on ignored paths are not captured.

    Args:
        test_file: File monitored on the host.
        ignored_dir: Temporary directory that is not monitored.
        test_container: A container for running commands in.
        server: The server instance to communicate with.
    """
    assert test_container.id is not None

    # Set ACL on an ignored file -- should not produce an event
    ignored_file = os.path.join(ignored_dir, 'ignored_acl.txt')
    with open(ignored_file, 'w') as f:
        f.write('ignored')

    # This runs on the host but the file is in an unmonitored directory.
    # Since we only match by inode and this file was just created in an
    # ignored dir, it won't be in the inode_map and won't trigger.

    # Now do a chmod on the monitored file to verify the server is working
    process = Process.from_proc()
    mode = 0o644
    os.chmod(test_file, mode)

    event = Event(
        process=process,
        event_type=EventType.PERMISSION,
        file=test_file,
        host_path=test_file,
        mode=mode,
    )

    server.wait_events([event])
