from __future__ import annotations

import os

from event import Event, EventType, Process
from server import FileActivityService
from utils import get_metric_value


def get_kernel_setxattr_added(fact_config: tuple[dict, str]):
    """
    Query Prometheus metrics to get the count of setxattr events
    added to the ring buffer.

    Args:
        fact_config: The fact configuration tuple
            (config dict, config file path).

    Returns:
        The current value of
        kernel_inode_setxattr_events{label="Added"} metric.
    """
    value = get_metric_value(
        fact_config,
        'kernel_inode_setxattr_events',
        {'label': 'Added'},
    )
    return int(value) if value is not None else 0


def get_kernel_removexattr_added(fact_config: tuple[dict, str]):
    """
    Query Prometheus metrics to get the count of removexattr events
    added to the ring buffer.

    Args:
        fact_config: The fact configuration tuple
            (config dict, config file path).

    Returns:
        The current value of
        kernel_inode_removexattr_events{label="Added"} metric.
    """
    value = get_metric_value(
        fact_config,
        'kernel_inode_removexattr_events',
        {'label': 'Added'},
    )
    return int(value) if value is not None else 0


def test_setxattr(
    test_file: str,
    fact_config: tuple[dict, str],
):
    """
    Tests that setting a user xattr on a monitored file is tracked
    via kernel metrics.

    The test_file fixture creates a file before fact starts, so it is
    picked up by the initial scan and its inode is already tracked.

    Args:
        test_file: File monitored on the host.
        fact_config: The fact configuration.
    """
    initial = get_kernel_setxattr_added(fact_config)

    os.setxattr(test_file, 'user.fact_test', b'test_value')

    final = get_kernel_setxattr_added(fact_config)
    delta = final - initial
    assert delta == 1, f'Expected exactly 1 setxattr event added, got {delta}'


def test_removexattr(
    test_file: str,
    fact_config: tuple[dict, str],
):
    """
    Tests that removing a user xattr from a monitored file is tracked
    via kernel metrics.

    Args:
        test_file: File monitored on the host.
        fact_config: The fact configuration.
    """
    os.setxattr(test_file, 'user.fact_remove', b'to_remove')

    initial = get_kernel_removexattr_added(fact_config)

    os.removexattr(test_file, 'user.fact_remove')

    final = get_kernel_removexattr_added(fact_config)
    delta = final - initial
    assert delta == 1, (
        f'Expected exactly 1 removexattr event added, got {delta}'
    )


def test_setxattr_multiple(
    test_file: str,
    fact_config: tuple[dict, str],
):
    """
    Tests that setting multiple xattrs on a monitored file tracks
    all of them.

    Args:
        test_file: File monitored on the host.
        fact_config: The fact configuration.
    """
    initial = get_kernel_setxattr_added(fact_config)

    os.setxattr(test_file, 'user.attr1', b'value1')
    os.setxattr(test_file, 'user.attr2', b'value2')
    os.setxattr(test_file, 'user.attr3', b'value3')

    final = get_kernel_setxattr_added(fact_config)
    delta = final - initial
    assert delta == 3, f'Expected exactly 3 setxattr events added, got {delta}'


def test_setxattr_ignored(
    test_file: str,
    ignored_dir: str,
    fact_config: tuple[dict, str],
):
    """
    Tests that xattr changes on unmonitored files are not tracked,
    while xattr changes on monitored files are.

    Args:
        test_file: File monitored on the host.
        ignored_dir: Temporary directory that is not monitored by fact.
        fact_config: The fact configuration.
    """
    ignored_file = os.path.join(ignored_dir, 'ignored.txt')
    with open(ignored_file, 'w') as f:
        f.write('ignored')

    initial = get_kernel_setxattr_added(fact_config)

    os.setxattr(ignored_file, 'user.ignored', b'value')

    after_ignored = get_kernel_setxattr_added(fact_config)
    assert after_ignored == initial, (
        'Setting xattr on ignored file should not increment Added metric'
    )

    os.setxattr(test_file, 'user.monitored', b'value')

    final = get_kernel_setxattr_added(fact_config)
    delta = final - initial
    assert delta == 1, (
        f'Expected exactly 1 setxattr event (monitored file only), got {delta}'
    )


def test_setxattr_new_file(
    monitored_dir: str,
    server: FileActivityService,
    fact_config: tuple[dict, str],
):
    """
    Tests that xattr tracking works for files created while fact is
    running, not just files from the initial scan.

    A new file is created in the monitored directory and its creation
    event is awaited to ensure the inode is tracked before setting
    an xattr.

    Args:
        monitored_dir: Temporary directory path that is monitored.
        server: The server instance to communicate with.
        fact_config: The fact configuration.
    """
    process = Process.from_proc()

    test_file = os.path.join(monitored_dir, 'xattr_new.txt')
    with open(test_file, 'w') as f:
        f.write('new file')

    server.wait_events([
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=test_file,
            host_path=test_file,
        ),
    ])

    initial = get_kernel_setxattr_added(fact_config)

    os.setxattr(test_file, 'user.new_file', b'value')

    final = get_kernel_setxattr_added(fact_config)
    delta = final - initial
    assert delta == 1, f'Expected exactly 1 setxattr event added, got {delta}'
