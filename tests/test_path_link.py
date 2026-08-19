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
            host_path=hardlink,
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
            host_path=link1,
        ),
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=link2,
            host_path=link2,
        ),
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=link3,
            host_path=link3,
        ),
    ]

    server.wait_events(events)


def test_link_in_subdirectory(monitored_dir: str, server: EventServer):
    """
    Tests hardlinks in different subdirectories of the monitored path.

    Args:
        monitored_dir: Temporary directory path for creating test files.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()

    # Create subdirectories
    dir1 = os.path.join(monitored_dir, 'dir1')
    dir2 = os.path.join(monitored_dir, 'dir2')
    os.makedirs(dir1)
    os.makedirs(dir2)

    # Create original file in dir1
    original = os.path.join(dir1, 'file.txt')
    with open(original, 'w') as f:
        f.write('test content')

    # Create hardlink in dir2
    hardlink = os.path.join(dir2, 'file.txt')
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
            host_path=hardlink,
        ),
    ]

    server.wait_events(events)


def test_ignored(monitored_dir: str, ignored_dir: str, server: EventServer):
    """
    Tests that link events creating hardlinks in ignored directories
    are not captured by the server.

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

    # Only the original creation and monitored hardlink should be reported
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
            file=monitored_link,
            host_path=monitored_link,
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
    event, but what path should be reported?

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
    with open(ignored_link) as f:
        f.read()

    # Should we get an event? If so, what should host_path be?
    # The inode is tracked because monitored path exists.
    # Access via ignored path should either:
    # 1. Report the actual ignored path (probably empty host_path)
    # 2. Report the monitored path that is tracked
    events = [
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=monitored,
            host_path=monitored,
        ),
        # What event do we expect here?
        # This exposes the implementation question.
        Event(
            process=process,
            event_type=EventType.OPEN,
            file=ignored_link,
            host_path=monitored,
        ),  # Or host_path=''?
    ]

    server.wait_events(events)


def test_unlink_monitored_hardlink_with_ignored_remaining(
    monitored_dir: str, ignored_dir: str, server: EventServer
):
    """
    Tests unlinking the monitored hardlink when an unmonitored hardlink
    still exists. Should inode tracking be removed?

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

    # The inode should be removed from tracking even though
    # the ignored hardlink still exists (file not deleted from filesystem)
    # Verify this by trying to access via ignored link - should not generate
    # event
    with open(ignored_link, 'w') as f:
        f.write('This is a test')

    # Only creation and unlink events expected, no open event
    events = [
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=monitored,
            host_path=monitored,
        ),
        Event(
            process=process,
            event_type=EventType.UNLINK,
            file=monitored,
            host_path=monitored,
        ),
    ]

    server.wait_events(events)


def test_multiple_monitored_and_ignored_hardlinks(
    monitored_dir: str, ignored_dir: str, server: EventServer
):
    """
    Tests complex scenario with multiple hardlinks in both monitored
    and ignored paths.

    Args:
        monitored_dir: Temporary directory path for creating test files.
        ignored_dir: Temporary directory path that is not monitored by fact.
        server: The server instance to communicate with.
    """
    process = Process.from_proc()

    # Create file in monitored directory
    monitored1 = os.path.join(monitored_dir, 'file1.txt')
    with open(monitored1, 'w') as f:
        f.write('test content')

    # Create multiple hardlinks
    monitored2 = os.path.join(monitored_dir, 'file2.txt')
    ignored1 = os.path.join(ignored_dir, 'file1.txt')
    ignored2 = os.path.join(ignored_dir, 'file2.txt')

    os.link(monitored1, monitored2)
    os.link(monitored1, ignored1)
    os.link(monitored1, ignored2)

    # Unlink one monitored path
    os.unlink(monitored1)

    # Access via remaining monitored path should still work
    with open(monitored2) as f:
        f.read()

    events = [
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=monitored1,
            host_path=monitored1,
        ),
        Event(
            process=process,
            event_type=EventType.CREATION,
            file=monitored2,
            host_path=monitored2,
        ),
        Event(
            process=process,
            event_type=EventType.UNLINK,
            file=monitored1,
            host_path=monitored1,
        ),
        Event(
            process=process,
            event_type=EventType.OPEN,
            file=monitored2,
            host_path=monitored2,
        ),
    ]

    server.wait_events(events)
