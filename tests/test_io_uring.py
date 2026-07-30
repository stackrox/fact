from __future__ import annotations

import os
import subprocess

import pytest

from event import Event, EventType, Process
from server import EventServer

IO_URING_SRC = os.path.join(os.path.dirname(__file__), 'io_uring_write_raw.c')
IO_URING_BIN = os.path.join(os.path.dirname(__file__), 'io_uring_write_raw')


@pytest.fixture(scope='session')
def io_uring_helper():
    """Compile the raw io_uring helper statically. Skips if glibc-static is unavailable."""
    result = subprocess.run(
        ['cc', '-static', '-o', IO_URING_BIN, IO_URING_SRC],
        capture_output=True,
    )
    if result.returncode != 0:
        pytest.skip(
            'io_uring helper compilation failed (glibc-static missing?): '
            + result.stderr.decode()
        )
    yield IO_URING_BIN
    if os.path.exists(IO_URING_BIN):
        os.unlink(IO_URING_BIN)


def test_io_uring_write(
    monitored_dir: str,
    server: EventServer,
    io_uring_helper: str,
):
    """
    Verifies that io_uring write operations modify files but are not
    currently tracked by fact.

    Creates a file with 'hi', modifies it to 'bye' via io_uring
    (open, write, and close all go through io_uring, bypassing the
    normal syscall path), then verifies the content changed and that
    only the expected creation events are captured.
    """
    fut = os.path.join(monitored_dir, 'io_uring_test.txt')
    process = Process.from_proc()

    # Create file with initial content via normal I/O.
    with open(fut, 'w') as f:
        f.write('hi')

    creation = Event(
        process=process,
        event_type=EventType.CREATION,
        file=fut,
        host_path=fut,
    )
    server.wait_events([creation])

    # Modify the file using io_uring (bypasses normal syscall path).
    result = subprocess.run(
        [io_uring_helper, fut, 'bye'],
        capture_output=True,
    )
    if result.returncode == 2:
        pytest.skip(
            f'io_uring not supported: {result.stderr.decode()}'
        )
    assert result.returncode == 0, (
        f'io_uring write failed: {result.stderr.decode()}'
    )

    # Create a sentinel file via normal I/O to verify event ordering.
    # With strict=True (the default), any unexpected event appearing
    # before the sentinel would cause the test to fail.
    sentinel = os.path.join(monitored_dir, 'sentinel.txt')
    with open(sentinel, 'w') as f:
        f.write('sentinel')

    sentinel_event = Event(
        process=process,
        event_type=EventType.CREATION,
        file=sentinel,
        host_path=sentinel,
    )
    server.wait_events([sentinel_event])

    # Verify the file was actually modified by io_uring.
    with open(fut) as f:
        assert f.read() == 'bye'
