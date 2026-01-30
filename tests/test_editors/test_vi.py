from event import Event, EventType, Process
from test_editors.commons import get_vi_test_file


def test_new_file(vi_container, server):
    fut = '/mounted/test.txt'
    swap_file = '/mounted/.test.txt.swp'
    swx_file = '/mounted/.test.txt.swx'
    exe = '/usr/libexec/vi'

    vi_container.exec_run(
        f"vi {fut} +':normal iThis is a test<CR>' -c x")

    process = Process.in_container(
        exe_path=exe,
        args=f'{exe} {fut} +:normal iThis is a test<CR> -c x',
        name='vi',
        container_id=vi_container.id[:12],
    )

    events = [
        Event(process=process, event_type=EventType.CREATION,
              file=swap_file, host_path=''),
        Event(process=process, event_type=EventType.CREATION,
              file=swx_file, host_path=''),
        Event(process=process, event_type=EventType.UNLINK,
              file=swx_file, host_path=''),
        Event(process=process, event_type=EventType.UNLINK,
              file=swap_file, host_path=''),
        Event(process=process, event_type=EventType.CREATION,
              file=swap_file, host_path=''),
        Event(process=process, event_type=EventType.CREATION,
              file=fut, host_path=''),
        Event(process=process, event_type=EventType.UNLINK,
              file=swap_file, host_path=''),
    ]

    for e in events:
        print(f'Waiting for event: {e}')

    server.wait_events(events, strict=True)


def test_new_file_ovfs(vi_container, server):
    fut = '/container-dir/test.txt'
    swap_file = '/container-dir/.test.txt.swp'
    swx_file = '/container-dir/.test.txt.swx'
    exe = '/usr/libexec/vi'

    vi_container.exec_run(
        f"vi {fut} +':normal iThis is a test<CR>' -c x")

    process = Process.in_container(
        exe_path=exe,
        args=f'{exe} {fut} +:normal iThis is a test<CR> -c x',
        name='vi',
        container_id=vi_container.id[:12],
    )

    events = [
        Event(process=process, event_type=EventType.CREATION,
              file=swap_file, host_path=''),
        Event(process=process, event_type=EventType.OPEN,
              file=swap_file, host_path=''),
        Event(process=process, event_type=EventType.CREATION,
              file=swx_file, host_path=''),
        Event(process=process, event_type=EventType.OPEN,
              file=swx_file, host_path=''),
        Event(process=process, event_type=EventType.UNLINK,
              file=swx_file, host_path=''),
        Event(process=process, event_type=EventType.UNLINK,
              file=swap_file, host_path=''),
        Event(process=process, event_type=EventType.CREATION,
              file=swap_file, host_path=''),
        Event(process=process, event_type=EventType.OPEN,
              file=swap_file, host_path=''),
        Event(process=process, event_type=EventType.CREATION,
              file=fut, host_path=''),
        Event(process=process, event_type=EventType.OPEN,
              file=fut, host_path=''),
        Event(process=process, event_type=EventType.UNLINK,
              file=swap_file, host_path=''),
    ]

    for e in events:
        print(f'Waiting for event: {e}')

    server.wait_events(events, strict=True)


def test_open_file(vi_container, server):
    fut = '/mounted/test.txt'
    swap_file = '/mounted/.test.txt.swp'
    swx_file = '/mounted/.test.txt.swx'
    vi_test_file = get_vi_test_file('/mounted')
    exe = '/usr/libexec/vi'
    container_id = vi_container.id[:12]

    # We ensure the file exists before editing.
    vi_container.exec_run(f'touch {fut}')
    vi_container.exec_run(
        f"vi {fut} +':normal iThis is a test<CR>' -c x")

    touch_process = Process.in_container(
        exe_path='/usr/bin/touch',
        args=f'touch {fut}',
        name='touch',
        container_id=container_id,
    )
    vi_process = Process.in_container(
        exe_path=exe,
        args=f'{exe} {fut} +:normal iThis is a test<CR> -c x',
        name='vi',
        container_id=container_id,
    )

    events = [
        Event(process=touch_process, event_type=EventType.CREATION,
              file=fut, host_path=''),
        Event(process=vi_process, event_type=EventType.CREATION,
              file=swap_file, host_path=''),
        Event(process=vi_process, event_type=EventType.CREATION,
              file=swx_file, host_path=''),
        Event(process=vi_process, event_type=EventType.UNLINK,
              file=swx_file, host_path=''),
        Event(process=vi_process, event_type=EventType.UNLINK,
              file=swap_file, host_path=''),
        Event(process=vi_process, event_type=EventType.CREATION,
              file=swap_file, host_path=''),
        Event(process=vi_process, event_type=EventType.PERMISSION,
              file=swap_file, host_path='', mode=0o644),
        Event(process=vi_process, event_type=EventType.CREATION,
              file=vi_test_file, host_path=''),
        Event(process=vi_process, event_type=EventType.OWNERSHIP,
              file=vi_test_file, host_path='', owner_uid=0, owner_gid=0),
        Event(process=vi_process, event_type=EventType.UNLINK,
              file=vi_test_file, host_path=''),
        Event(process=vi_process, event_type=EventType.CREATION,
              file=fut, host_path=''),
        Event(process=vi_process, event_type=EventType.PERMISSION,
              file=fut, host_path='', mode=0o100644),
        Event(process=vi_process, event_type=EventType.UNLINK,
              file=f'{fut}~', host_path=''),
        Event(process=vi_process, event_type=EventType.UNLINK,
              file=swap_file, host_path=''),
    ]

    for e in events:
        print(f'Waiting for event: {e}')

    server.wait_events(events, strict=True)


def test_open_file_ovfs(vi_container, server):
    fut = '/container-dir/test.txt'
    swap_file = '/container-dir/.test.txt.swp'
    swx_file = '/container-dir/.test.txt.swx'
    vi_test_file = get_vi_test_file('/container-dir')
    exe = '/usr/libexec/vi'
    container_id = vi_container.id[:12]

    # We ensure the file exists before editing.
    vi_container.exec_run(f'touch {fut}')
    vi_container.exec_run(
        f"vi {fut} +':normal iThis is a test<CR>' -c x")

    touch_process = Process.in_container(
        exe_path='/usr/bin/touch',
        args=f'touch {fut}',
        name='touch',
        container_id=container_id,
    )
    vi_process = Process.in_container(
        exe_path=exe,
        args=f'{exe} {fut} +:normal iThis is a test<CR> -c x',
        name='vi',
        container_id=container_id,
    )

    events = [
        Event(process=touch_process, event_type=EventType.CREATION,
              file=fut, host_path=''),
        Event(process=touch_process, event_type=EventType.OPEN,
              file=fut, host_path=''),
        Event(process=vi_process, event_type=EventType.CREATION,
              file=swap_file, host_path=''),
        Event(process=vi_process, event_type=EventType.OPEN,
              file=swap_file, host_path=''),
        Event(process=vi_process, event_type=EventType.CREATION,
              file=swx_file, host_path=''),
        Event(process=vi_process, event_type=EventType.OPEN,
              file=swx_file, host_path=''),
        Event(process=vi_process, event_type=EventType.UNLINK,
              file=swx_file, host_path=''),
        Event(process=vi_process, event_type=EventType.UNLINK,
              file=swap_file, host_path=''),
        Event(process=vi_process, event_type=EventType.CREATION,
              file=swap_file, host_path=''),
        Event(process=vi_process, event_type=EventType.OPEN,
              file=swap_file, host_path=''),
        Event(process=vi_process, event_type=EventType.PERMISSION,
              file=swap_file, host_path='', mode=0o644),
        Event(process=vi_process, event_type=EventType.CREATION,
              file=vi_test_file, host_path=''),
        Event(process=vi_process, event_type=EventType.OPEN,
              file=vi_test_file, host_path=''),
        Event(process=vi_process, event_type=EventType.OWNERSHIP,
              file=vi_test_file, host_path='', owner_uid=0, owner_gid=0),
        Event(process=vi_process, event_type=EventType.UNLINK,
              file=vi_test_file, host_path=''),
        Event(process=vi_process, event_type=EventType.CREATION,
              file=fut, host_path=''),
        Event(process=vi_process, event_type=EventType.OPEN,
              file=fut, host_path=''),
        Event(process=vi_process, event_type=EventType.PERMISSION,
              file=fut, host_path='', mode=0o100644),
        Event(process=vi_process, event_type=EventType.UNLINK,
              file=f'{fut}~', host_path=''),
        Event(process=vi_process, event_type=EventType.UNLINK,
              file=swap_file, host_path=''),
    ]

    for e in events:
        print(f'Waiting for event: {e}')

    server.wait_events(events, strict=True)
