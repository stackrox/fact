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
    test_container.exec_run(f'touch {fut}')
    test_container.exec_run(f'chown {TEST_UID}:{TEST_GID} {fut}')

    loginuid = pow(2, 32) - 1
    touch = Process(pid=None,
                    uid=0,
                    gid=0,
                    exe_path='/usr/bin/touch',
                    args=f'touch {fut}',
                    name='touch',
                    container_id=test_container.id[:12],
                    loginuid=loginuid)
    chown = Process(pid=None,
                   uid=0,
                   gid=0,
                   exe_path='/usr/bin/chown',
                   args=f'chown {TEST_UID}:{TEST_GID} {fut}',
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
        test_container.exec_run(f'touch {fut}')
        test_container.exec_run(f'chown {TEST_UID}:{TEST_GID} {fut}')

        touch = Process(pid=None,
                        uid=0,
                        gid=0,
                        exe_path='/usr/bin/touch',
                        args=f'touch {fut}',
                        name='touch',
                        container_id=test_container.id[:12],
                        loginuid=loginuid)
        chown = Process(pid=None,
                       uid=0,
                       gid=0,
                       exe_path='/usr/bin/chown',
                       args=f'chown {TEST_UID}:{TEST_GID} {fut}',
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

    test_container.exec_run(f'touch {ignored_file}')
    test_container.exec_run(f'chown {TEST_UID}:{TEST_GID} {ignored_file}')
    test_container.exec_run(f'touch {monitored_file}')
    test_container.exec_run(f'chown {TEST_UID}:{TEST_GID} {monitored_file}')

    ignored_touch = Process(pid=None,
                            uid=0,
                            gid=0,
                            exe_path='/usr/bin/touch',
                            args=f'touch {ignored_file}',
                            name='touch',
                            container_id=test_container.id[:12],
                            loginuid=loginuid)
    ignored_chown = Process(pid=None,
                            uid=0,
                            gid=0,
                            exe_path='/usr/bin/chown',
                            args=f'chown {TEST_UID}:{TEST_GID} {ignored_file}',
                            name='chown',
                            container_id=test_container.id[:12],
                            loginuid=loginuid)
    reported_touch = Process(pid=None,
                             uid=0,
                             gid=0,
                             exe_path='/usr/bin/touch',
                             args=f'touch {monitored_file}',
                             name='touch',
                             container_id=test_container.id[:12],
                             loginuid=loginuid)
    reported_chown = Process(pid=None,
                             uid=0,
                             gid=0,
                             exe_path='/usr/bin/chown',
                             args=f'chown {TEST_UID}:{TEST_GID} {monitored_file}',
                             name='chown',
                             container_id=test_container.id[:12],
                             loginuid=loginuid)

    # events
    ignored_create_event = Event(process=ignored_touch,
                                 event_type=EventType.CREATION,
                                 file=ignored_file,
                                 host_path='')
    reported_create_event = Event(process=reported_touch,
                                  event_type=EventType.CREATION,
                                  file=monitored_file,
                                  host_path='')
    ignored_chmod_event = Event(process=ignored_chown,
                          event_type=EventType.OWNERSHIP,
                          file=ignored_file,
                          host_path='',
                          owner_uid=TEST_UID,
                          owner_gid=TEST_GID)
    reported_chmod_event = Event(process=reported_chown,
                           event_type=EventType.OWNERSHIP,
                           file=monitored_file,
                           host_path='',
                           owner_uid=TEST_UID,
                           owner_gid=TEST_GID)

    server.wait_events(events=[reported_create_event, reported_chmod_event],
                       ignored=[ignored_create_event, ignored_chmod_event])


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

    # Create the file
    test_container.exec_run(f'touch {fut}')

    # First chown to TEST_UID:TEST_GID - this should trigger an event
    test_container.exec_run(f'chown {TEST_UID}:{TEST_GID} {fut}')

    # Second chown to the same UID/GID - this should ALSO trigger an event
    test_container.exec_run(f'chown {TEST_UID}:{TEST_GID} {fut}')

    loginuid = pow(2, 32) - 1
    touch = Process(pid=None,
                    uid=0,
                    gid=0,
                    exe_path='/usr/bin/touch',
                    args=f'touch {fut}',
                    name='touch',
                    container_id=test_container.id[:12],
                    loginuid=loginuid)
    chown1 = Process(pid=None,
                    uid=0,
                    gid=0,
                    exe_path='/usr/bin/chown',
                    args=f'chown {TEST_UID}:{TEST_GID} {fut}',
                    name='chown',
                    container_id=test_container.id[:12],
                    loginuid=loginuid)
    chown2 = Process(pid=None,
                    uid=0,
                    gid=0,
                    exe_path='/usr/bin/chown',
                    args=f'chown {TEST_UID}:{TEST_GID} {fut}',
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

