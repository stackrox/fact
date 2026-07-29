import os
import subprocess
from time import sleep

import pytest
import requests

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0,
    reason='mount operations require root access',
)


def get_inodes() -> dict[str, str]:
    FACT_INTROSPECTION_INODES = 'http://127.0.0.1:9000/inodes'
    res = requests.get(FACT_INTROSPECTION_INODES, timeout=5)
    res.raise_for_status()
    return res.json()


def assert_tracked_path(monitored_dir: str):
    stat = os.stat(monitored_dir)
    inode = f'{stat.st_dev}:{stat.st_ino}'

    for _ in range(3):
        try:
            res = get_inodes()
            assert res[inode] == monitored_dir
            return
        except KeyError as e:
            print(f'Failed to find inode: {e}')
            sleep(1)

    raise TimeoutError


@pytest.fixture
def cleanup_mount(monitored_dir: str):
    yield
    if os.path.ismount(monitored_dir):
        subprocess.run(['umount', monitored_dir], check=True)


def test_mount(
    monitored_dir: str,
    cleanup_mount: None,
):
    assert_tracked_path(monitored_dir)

    subprocess.run(
        ['mount', '-t', 'tmpfs', '-o', 'size=10M', 'tmpfs', monitored_dir],
        check=True,
    )
    assert_tracked_path(monitored_dir)

    subprocess.run(['umount', monitored_dir], check=True)
    assert_tracked_path(monitored_dir)
