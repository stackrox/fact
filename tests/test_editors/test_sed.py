import re
from event import Event, EventType, Process


def test_sed(vi_container, server):
    # File Under Test
    fut = '/mounted/test.txt'
    container_id = vi_container.id[:12]

    vi_container.exec_run(f"sh -c \"echo 'This is a test' > {fut}\"")
    vi_container.exec_run(fr"sed -i -e 's/a test/not \0/' {fut}")

    shell = Process.in_container(
        exe_path='/usr/bin/bash',
        args=f"sh -c echo 'This is a test' > {fut}",
        name='sh',
        container_id=container_id,
    )
    sed = Process.in_container(
        exe_path='/usr/bin/sed',
        args=fr'sed -i -e s/a test/not \0/ {fut}',
        name='sed',
        container_id=container_id,
    )

    sed_tmp_file = re.compile(r'\/mounted\/sed[0-9a-zA-Z]{6}')

    events = [
        Event(process=shell, event_type=EventType.CREATION,
              file=fut, host_path=''),
        Event(process=sed, event_type=EventType.CREATION,
              file=sed_tmp_file, host_path=''),
        Event(process=sed, event_type=EventType.OWNERSHIP,
              file=sed_tmp_file, host_path='', owner_uid=0, owner_gid=0),
    ]

    for e in events:
        print(f'Waiting for event: {e}')

    server.wait_events(events, strict=True)


def test_sed_ovfs(vi_container, server):
    # File Under Test
    fut = '/container-dir/test.txt'
    container_id = vi_container.id[:12]

    vi_container.exec_run(f"sh -c \"echo 'This is a test' > {fut}\"")
    vi_container.exec_run(fr"sed -i -e 's/a test/not \0/' {fut}")

    shell = Process.in_container(
        exe_path='/usr/bin/bash',
        args=f"sh -c echo 'This is a test' > {fut}",
        name='sh',
        container_id=container_id,
    )
    sed = Process.in_container(
        exe_path='/usr/bin/sed',
        args=fr'sed -i -e s/a test/not \0/ {fut}',
        name='sed',
        container_id=container_id,
    )

    sed_tmp_file = re.compile(r'\/container-dir\/sed[0-9a-zA-Z]{6}')

    events = [
        Event(process=shell, event_type=EventType.CREATION,
              file=fut, host_path=''),
        Event(process=shell, event_type=EventType.OPEN,
              file=fut, host_path=''),
        Event(process=sed, event_type=EventType.CREATION,
              file=sed_tmp_file, host_path=''),
        Event(process=sed, event_type=EventType.OPEN,
              file=sed_tmp_file, host_path=''),
        Event(process=sed, event_type=EventType.OWNERSHIP,
              file=sed_tmp_file, host_path='', owner_uid=0, owner_gid=0),
    ]

    for e in events:
        print(f'Waiting for event: {e}')

    server.wait_events(events, strict=True)
