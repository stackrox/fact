import os

from event import Event, EventType, Process
from server import EventServer


def test_link(monitored_dir: str, server: EventServer):
    """
    Tests the creation of a hardlink and verifies that the corresponding
    event is captured by the server.

    Args:
        monitored_dir: Temporary directory path for creating test files.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()

    # Create original file
    original = os.path.join(monitored_dir, 'original.txt')
    with open(original, 'w') as f:
        f.write('test content')

    # Create hardlink
    hardlink = os.path.join(monitored_dir, 'hardlink.txt')
    os.link(original, hardlink)

    events = [
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=original,
            host_path=original,
        ),
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=hardlink,
            host_path=original,
        ),
    ]

    server.wait_events(events)


def test_multiple_hardlinks(monitored_dir: str, server: EventServer):
    """
    Tests creating multiple hardlinks to the same file.
    All paths should be tracked independently.

    Args:
        monitored_dir: Temporary directory path for creating test files.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()

    # Create original file
    original = os.path.join(monitored_dir, 'original.txt')
    with open(original, 'w') as f:
        f.write('test content')

    # Create multiple hardlinks
    link1 = os.path.join(monitored_dir, 'link1.txt')
    link2 = os.path.join(monitored_dir, 'link2.txt')
    link3 = os.path.join(monitored_dir, 'link3.txt')

    os.link(original, link1)
    os.link(original, link2)
    os.link(original, link3)

    events = [
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=original,
            host_path=original,
        ),
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=link1,
            host_path=original,
        ),
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=link2,
            host_path=original,
        ),
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=link3,
            host_path=original,
        ),
    ]

    server.wait_events(events)


def test_access_after_remove(monitored_dir: str, server: EventServer):
    """
    Tests creating multiple hardlinks to the same file.
    Remove some, and access via one of them.

    Args:
        monitored_dir: Temporary directory path for creating test files.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()

    # Create original file
    original = os.path.join(monitored_dir, 'original.txt')
    with open(original, 'w') as f:
        f.write('test content')

    # Create multiple hardlinks
    link1 = os.path.join(monitored_dir, 'link1.txt')
    link2 = os.path.join(monitored_dir, 'link2.txt')
    link3 = os.path.join(monitored_dir, 'link3.txt')

    os.link(original, link1)
    os.link(original, link2)
    os.link(original, link3)

    # The OPEN event should still be emitted since the inode is still tracked.
    os.unlink(link1)

    with open(link2, 'w') as f:
        f.write('test content')

    events = [
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=original,
            host_path=original,
        ),
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=link1,
            host_path=original,
        ),
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=link2,
            host_path=original,
        ),
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=link3,
            host_path=original,
        ),
        Event(
            process=process,
            event_type=EventType.UNLINK,
            file=link1,
            host_path=original,
        ),
        Event(
            process=process,
            event_type=EventType.OPEN,
            file=link2,
            host_path=original,
        ),
    ]

    server.wait_events(events)


def test_ignored(monitored_dir: str, ignored_dir: str, server: EventServer):
    """
    Tests that link events creating hardlinks in ignored directories
    is captured via inode tracking.

    Args:
        monitored_dir: Temporary directory path for creating test files.
        ignored_dir: Temporary directory path that is not monitored by fact.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()

    # Create original file in monitored directory
    original = os.path.join(monitored_dir, 'original.txt')
    with open(original, 'w') as f:
        f.write('test content')

    # Create hardlink in ignored directory
    ignored_link = os.path.join(ignored_dir, 'link.txt')
    os.link(original, ignored_link)

    # Create hardlink in monitored directory
    monitored_link = os.path.join(monitored_dir, 'link.txt')
    os.link(original, monitored_link)

    # The hardlink in the ignored directory must be reported with the
    # original host_path, since this is the basis of how inode tracking
    # works.
    events = [
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=original,
            host_path=original,
        ),
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=ignored_link,
            host_path=original,
        ),
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=monitored_link,
            host_path=original,
        ),
    ]

    server.wait_events(events)


def test_link_from_ignored_to_monitored(
    monitored_dir: str, ignored_dir: str, server: EventServer
):
    """
    Tests creating a hardlink in a monitored path when the original file
    is in an ignored path. The inode should start being tracked.

    Args:
        monitored_dir: Temporary directory path for creating test files.
        ignored_dir: Temporary directory path that is not monitored by fact.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()

    # Create original file in IGNORED directory
    original = os.path.join(ignored_dir, 'original.txt')
    with open(original, 'w') as f:
        f.write('test content')

    # Create hardlink in MONITORED directory
    monitored_link = os.path.join(monitored_dir, 'link.txt')
    os.link(original, monitored_link)

    # Only the monitored hardlink creation should be reported
    events = [
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=monitored_link,
            host_path=monitored_link,
        ),
    ]

    server.wait_events(events)


def test_access_via_unmonitored_hardlink(
    monitored_dir: str, ignored_dir: str, server: EventServer
):
    """
    Tests accessing a file via an unmonitored hardlink when a monitored
    hardlink exists. The inode is tracked, so access should generate an
    event.

    Args:
        monitored_dir: Temporary directory path for creating test files.
        ignored_dir: Temporary directory path that is not monitored by fact.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()

    # Create file in monitored directory
    monitored = os.path.join(monitored_dir, 'file.txt')
    with open(monitored, 'w') as f:
        f.write('test content')

    # Create hardlink in ignored directory
    ignored_link = os.path.join(ignored_dir, 'link.txt')
    os.link(monitored, ignored_link)

    # Access via the IGNORED hardlink
    with open(ignored_link, 'w') as f:
        f.write('This is a test')

    events = [
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=monitored,
            host_path=monitored,
        ),
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=ignored_link,
            host_path=monitored,
        ),
        Event(
            process=process,
            event_type=EventType.OPEN,
            file=ignored_link,
            host_path=monitored,
        ),
    ]

    server.wait_events(events)


def test_unlink_monitored_hardlink_with_ignored_remaining(
    monitored_dir: str, ignored_dir: str, server: EventServer
):
    """
    Tests unlinking the monitored hardlink when an unmonitored hardlink
    still exists.

    Args:
        monitored_dir: Temporary directory path for creating test files.
        ignored_dir: Temporary directory path that is not monitored by fact.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()

    # Create file in monitored directory
    monitored = os.path.join(monitored_dir, 'file.txt')
    with open(monitored, 'w') as f:
        f.write('test content')

    # Create hardlink in ignored directory
    ignored_link = os.path.join(ignored_dir, 'link.txt')
    os.link(monitored, ignored_link)

    # Unlink the MONITORED path
    os.unlink(monitored)

    with open(ignored_link) as f:
        f.read()

    # used to drain the event queue and check for a "non-event"
    sentinel = os.path.join(monitored_dir, 'sentinel.txt')
    with open(sentinel, 'w') as f:
        f.write('sentinel')

    events = [
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=monitored,
            host_path=monitored,
        ),
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=ignored_link,
            host_path=monitored,
        ),
        Event(
            process=process,
            event_type=EventType.UNLINK,
            file=monitored,
            host_path=monitored,
        ),
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=sentinel,
            host_path=sentinel,
        ),
    ]

    server.wait_events(events)
