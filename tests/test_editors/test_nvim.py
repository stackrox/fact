from event import Event, EventType, Process

from test_editors.commons import get_vi_test_file


def test_new_file(editor_container, server):
    fut = '/mounted/test.txt'

    editor_container.exec_run(
        f"nvim {fut} +':normal iThis is a test<CR>' -c x")

    process = Process.in_container(
        exe_path='/usr/bin/nvim',
        args=f'nvim {fut} +:normal iThis is a test<CR> -c x',
        name='nvim',
        container_id=editor_container.id[:12],
    )
    events = [
        Event(process=process, event_type=EventType.CREATION,
              file=fut, host_path=''),
    ]

    server.wait_events(events, strict=True)


def test_open_file(editor_container, server):
    fut = '/mounted/test.txt'
    container_id = editor_container.id[:12]

    # We ensure the file exists before editing.
    editor_container.exec_run(f'touch {fut}')
    editor_container.exec_run(
        f"nvim {fut} +':normal iThis is a test<CR>' -c x")

    touch = Process.in_container(
        exe_path='/usr/bin/touch',
        args=f'touch {fut}',
        name='touch',
        container_id=container_id,
    )
    nvim = Process.in_container(
        exe_path='/usr/bin/nvim',
        args=f'nvim {fut} +:normal iThis is a test<CR> -c x',
        name='nvim',
        container_id=container_id,
    )

    vi_test_file = get_vi_test_file('/mounted')

    events = [
        Event(process=touch, event_type=EventType.CREATION,
              file=fut, host_path=''),
        Event(process=nvim, event_type=EventType.CREATION,
              file=vi_test_file, host_path=''),
        Event(process=nvim, event_type=EventType.OWNERSHIP,
              file=vi_test_file, host_path='', owner_uid=0, owner_gid=0),
        Event(process=nvim, event_type=EventType.UNLINK,
              file=vi_test_file, host_path=''),
        Event(process=nvim, event_type=EventType.CREATION,
              file=fut, host_path=''),
        Event(process=nvim, event_type=EventType.PERMISSION,
              file=fut, host_path='', mode=0o100644),
        Event(process=nvim, event_type=EventType.UNLINK,
              file=f'{fut}~', host_path=''),
    ]

    server.wait_events(events, strict=True)


def test_new_file_ovfs(editor_container, server):
    fut = '/container-dir/test.txt'

    editor_container.exec_run(
        f"nvim {fut} +':normal iThis is a test<CR>' -c x")

    process = Process.in_container(
        exe_path='/usr/bin/nvim',
        args=f'nvim {fut} +:normal iThis is a test<CR> -c x',
        name='nvim',
        container_id=editor_container.id[:12],
    )
    events = [
        Event(process=process, event_type=EventType.CREATION,
              file=fut, host_path=''),
        Event(process=process, event_type=EventType.OPEN,
              file=fut, host_path=''),
    ]

    server.wait_events(events, strict=True)


def test_open_file_ovfs(editor_container, server):
    fut = '/container-dir/test.txt'
    container_id = editor_container.id[:12]

    # We ensure the file exists before editing.
    editor_container.exec_run(f'touch {fut}')
    editor_container.exec_run(
        f"nvim {fut} +':normal iThis is a test<CR>' -c x")

    touch = Process.in_container(
        exe_path='/usr/bin/touch',
        args=f'touch {fut}',
        name='touch',
        container_id=container_id,
    )
    nvim = Process.in_container(
        exe_path='/usr/bin/nvim',
        args=f'nvim {fut} +:normal iThis is a test<CR> -c x',
        name='nvim',
        container_id=container_id,
    )

    vi_test_file = get_vi_test_file('/container-dir')

    events = [
        Event(process=touch, event_type=EventType.CREATION,
              file=fut, host_path=''),
        Event(process=touch, event_type=EventType.OPEN,
              file=fut, host_path=''),
        Event(process=nvim, event_type=EventType.CREATION,
              file=vi_test_file, host_path=''),
        Event(process=nvim, event_type=EventType.OPEN,
              file=vi_test_file, host_path=''),
        Event(process=nvim, event_type=EventType.OWNERSHIP,
              file=vi_test_file, host_path='', owner_uid=0, owner_gid=0),
        Event(process=nvim, event_type=EventType.UNLINK,
              file=vi_test_file, host_path=''),
        Event(process=nvim, event_type=EventType.CREATION,
              file=fut, host_path=''),
        Event(process=nvim, event_type=EventType.OPEN,
              file=fut, host_path=''),
        Event(process=nvim, event_type=EventType.PERMISSION,
              file=fut, host_path='', mode=0o100644),
        Event(process=nvim, event_type=EventType.UNLINK,
              file=f'{fut}~', host_path=''),
    ]

    server.wait_events(events, strict=True)
