import re
from event import Event, EventType, Process


def test_sed(fedora_container, server):
    assert fedora_container.id is not None
    # File Under Test
    fut = '/mounted/test.txt'
    create_cmd = f'sh -c "echo \'This is a test\' > {fut}"'
    sed_cmd = rf'sed -i -e "s/a test/not \\0/" {fut}'
    container_id = fedora_container.id[:12]

    fedora_container.exec_run(create_cmd)
    fedora_container.exec_run(sed_cmd)

    shell = Process.in_container(
        exe_path='/usr/bin/bash',
        args=create_cmd,
        name='sh',
        container_id=container_id,
    )
    sed = Process.in_container(
        exe_path='/usr/bin/sed',
        args=sed_cmd,
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
        Event(process=sed, event_type=EventType.RENAME,
              file=fut, host_path='', old_file=sed_tmp_file, old_host_path=''),
    ]

    server.wait_events(events, strict=True)


def test_sed_ovfs(fedora_container, server):
    assert fedora_container.id is not None
    # File Under Test
    fut = '/container-dir/test.txt'
    create_cmd = f'sh -c "echo \'This is a test\' > {fut}"'
    sed_cmd = rf'sed -i -e "s/a test/not \\0/" {fut}'
    container_id = fedora_container.id[:12]

    fedora_container.exec_run(create_cmd)
    fedora_container.exec_run(sed_cmd)

    shell = Process.in_container(
        exe_path='/usr/bin/bash',
        args=create_cmd,
        name='sh',
        container_id=container_id,
    )
    sed = Process.in_container(
        exe_path='/usr/bin/sed',
        args=sed_cmd,
        name='sed',
        container_id=container_id,
    )

    sed_tmp_file = re.compile(r'\/container-dir\/sed[0-9a-zA-Z]{6}')

    events = [
        Event(process=shell, event_type=EventType.CREATION,
              file=fut, host_path=''),
        Event(process=sed, event_type=EventType.CREATION,
              file=sed_tmp_file, host_path=''),
        Event(process=sed, event_type=EventType.OWNERSHIP,
              file=sed_tmp_file, host_path='', owner_uid=0, owner_gid=0),
        Event(process=sed, event_type=EventType.RENAME,
              file=fut, host_path='', old_file=sed_tmp_file, old_host_path=''),
    ]

    server.wait_events(events, strict=True)
