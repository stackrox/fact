import os

from event import Event, EventType, Process

# Tests here have to use a container to do 'chown',
# otherwise they would require to run as root.

# UID and GID values for chown tests
TEST_UID = 1234
TEST_GID = 2345


def test_chown(fact, test_container, server):
    """
    Execute a chown operation on a file and verifies the corresponding event is
    captured by the server.

    Args:
        fact: Fixture for file activity (only required to be running).
        test_container: A container for running commands in.
        server: The server instance to communicate with.
    """
    # File Under Test
    fut = '/container-dir/test.txt'

    # Create the file and chown it
    touch_cmd = f'touch {fut}'
    chown_cmd = f'chown {TEST_UID}:{TEST_GID} {fut}'
    test_container.exec_run(touch_cmd)
    test_container.exec_run(chown_cmd)

    loginuid = pow(2, 32) - 1
    touch = Process(pid=None,
                    uid=0,
                    gid=0,
                    exe_path='/usr/bin/touch',
                    args=touch_cmd,
                    name='touch',
                    container_id=test_container.id[:12],
                    loginuid=loginuid)
    chown = Process(pid=None,
                   uid=0,
                   gid=0,
                   exe_path='/usr/bin/chown',
                   args=chown_cmd,
                   name='chown',
                   container_id=test_container.id[:12],
                   loginuid=loginuid)
    events = [
        Event(process=touch, event_type=EventType.CREATION, file=fut,
              host_path=''),
        Event(process=chown, event_type=EventType.OWNERSHIP, file=fut,
              host_path='', owner_uid=TEST_UID, owner_gid=TEST_GID),
    ]

    for e in events:
        print(f'Waiting for event: {e}')

    server.wait_events(events)


def test_multiple(fact, test_container, server):
    """
    Tests ownership operations on multiple files and verifies the corresponding
    events are captured by the server.

    Args:
        fact: Fixture for file activity (only required to be running).
        test_container: A container for running commands in.
        server: The server instance to communicate with.
    """
    events = []
    loginuid = pow(2, 32) - 1

    # File Under Test
    for i in range(3):
        fut = f'/container-dir/{i}.txt'
        touch_cmd = f'touch {fut}'
        chown_cmd = f'chown {TEST_UID}:{TEST_GID} {fut}'
        test_container.exec_run(touch_cmd)
        test_container.exec_run(chown_cmd)

        touch = Process(pid=None,
                        uid=0,
                        gid=0,
                        exe_path='/usr/bin/touch',
                        args=touch_cmd,
                        name='touch',
                        container_id=test_container.id[:12],
                        loginuid=loginuid)
        chown = Process(pid=None,
                       uid=0,
                       gid=0,
                       exe_path='/usr/bin/chown',
                       args=chown_cmd,
                       name='chown',
                       container_id=test_container.id[:12],
                       loginuid=loginuid)

        events.extend([
            Event(process=touch, event_type=EventType.CREATION, file=fut,
                  host_path=''),
            Event(process=chown, event_type=EventType.OWNERSHIP, file=fut,
                  host_path='', owner_uid=TEST_UID, owner_gid=TEST_GID),
        ])

    for e in events:
        print(f'Waiting for event: {e}')

    server.wait_events(events)


def test_ignored(fact, test_container, monitored_dir, ignored_dir, server):
    """
    Tests that ownership events on ignored files are not captured by the
    server.

    Args:
        fact: Fixture for file activity (only required to be running).
        test_container: A container for running commands in.
        monitored_dir: Temporary directory path for creating the test file.
        ignored_dir: Temporary directory path that is not monitored by fact.
        server: The server instance to communicate with.
    """
    loginuid = pow(2, 32) - 1

    ignored_file = '/test.txt'
    monitored_file = '/container-dir/test.txt'

    ignored_touch_cmd = f'touch {ignored_file}'
    ignored_chown_cmd = f'chown {TEST_UID}:{TEST_GID} {ignored_file}'
    monitored_touch_cmd = f'touch {monitored_file}'
    monitored_chown_cmd = f'chown {TEST_UID}:{TEST_GID} {monitored_file}'

    test_container.exec_run(ignored_touch_cmd)
    test_container.exec_run(ignored_chown_cmd)
    test_container.exec_run(monitored_touch_cmd)
    test_container.exec_run(monitored_chown_cmd)

    ignored_touch = Process(pid=None,
                            uid=0,
                            gid=0,
                            exe_path='/usr/bin/touch',
                            args=ignored_touch_cmd,
                            name='touch',
                            container_id=test_container.id[:12],
                            loginuid=loginuid)
    ignored_chown = Process(pid=None,
                            uid=0,
                            gid=0,
                            exe_path='/usr/bin/chown',
                            args=ignored_chown_cmd,
                            name='chown',
                            container_id=test_container.id[:12],
                            loginuid=loginuid)
    reported_touch = Process(pid=None,
                             uid=0,
                             gid=0,
                             exe_path='/usr/bin/touch',
                             args=monitored_touch_cmd,
                             name='touch',
                             container_id=test_container.id[:12],
                             loginuid=loginuid)
    reported_chown = Process(pid=None,
                             uid=0,
                             gid=0,
                             exe_path='/usr/bin/chown',
                             args=monitored_chown_cmd,
                             name='chown',
                             container_id=test_container.id[:12],
                             loginuid=loginuid)

    ignored_create_event = Event(process=ignored_touch,
                                 event_type=EventType.CREATION,
                                 file=ignored_file,
                                 host_path='')
    reported_create_event = Event(process=reported_touch,
                                  event_type=EventType.CREATION,
                                  file=monitored_file,
                                  host_path='')
    ignored_chown_event = Event(process=ignored_chown,
                                event_type=EventType.OWNERSHIP,
                                file=ignored_file,
                                host_path='',
                                owner_uid=TEST_UID,
                                owner_gid=TEST_GID)
    reported_chown_event = Event(process=reported_chown,
                                 event_type=EventType.OWNERSHIP,
                                 file=monitored_file,
                                 host_path='',
                                 owner_uid=TEST_UID,
                                 owner_gid=TEST_GID)

    server.wait_events(events=[reported_create_event, reported_chown_event],
                       ignored=[ignored_create_event, ignored_chown_event])


def test_no_change(fact, test_container, server):
    """
    Tests that chown to the same UID/GID triggers events for all calls.

    Args:
        fact: Fixture for file activity (only required to be running).
        test_container: A container for running commands in.
        server: The server instance to communicate with.
    """
    # File Under Test
    fut = '/container-dir/test.txt'

    touch_cmd = f'touch {fut}'
    chown_cmd = f'chown {TEST_UID}:{TEST_GID} {fut}'

    # Create the file
    test_container.exec_run(touch_cmd)

    # First chown to TEST_UID:TEST_GID - this should trigger an event
    test_container.exec_run(chown_cmd)

    # Second chown to the same UID/GID - this should ALSO trigger an event
    test_container.exec_run(chown_cmd)

    loginuid = pow(2, 32) - 1
    touch = Process(pid=None,
                    uid=0,
                    gid=0,
                    exe_path='/usr/bin/touch',
                    args=touch_cmd,
                    name='touch',
                    container_id=test_container.id[:12],
                    loginuid=loginuid)
    chown1 = Process(pid=None,
                    uid=0,
                    gid=0,
                    exe_path='/usr/bin/chown',
                    args=chown_cmd,
                    name='chown',
                    container_id=test_container.id[:12],
                    loginuid=loginuid)
    chown2 = Process(pid=None,
                    uid=0,
                    gid=0,
                    exe_path='/usr/bin/chown',
                    args=chown_cmd,
                    name='chown',
                    container_id=test_container.id[:12],
                    loginuid=loginuid)

    # Expect both chown events (all calls to chown trigger events)
    events = [
        Event(process=touch, event_type=EventType.CREATION, file=fut,
              host_path=''),
        Event(process=chown1, event_type=EventType.OWNERSHIP, file=fut,
              host_path='', owner_uid=TEST_UID, owner_gid=TEST_GID),
        Event(process=chown2, event_type=EventType.OWNERSHIP, file=fut,
              host_path='', owner_uid=TEST_UID, owner_gid=TEST_GID),
    ]

    for e in events:
        print(f'Waiting for event: {e}')

    server.wait_events(events)

