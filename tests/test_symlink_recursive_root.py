from __future__ import annotations

import os
from time import sleep

import docker.models.containers
import yaml

from event import Event, EventType, Process
from server import EventServer


def reload_config(
    fact: docker.models.containers.Container, config: dict, config_file: str
):
    with open(config_file, 'w') as f:
        yaml.dump(config, f)
    fact.kill('SIGHUP')
    sleep(0.1)


def test_configured_relative_symlink_root_tracks_direct_child(
    fact: docker.models.containers.Container,
    fact_config: tuple[dict, str],
    ignored_dir: str,
    server: EventServer,
):
    """
    Regression test for ROX-36737.

    On RHCOS ``/root`` is a *relative* symlink to ``var/roothome``. When
    fact is configured with a recursive path rooted at that symlink
    (``/root/**``), creating a file directly beneath the symlink should
    emit a CREATION event.

    The bug: ``HostScanner::scan_inner()`` only tracks paths returned by
    ``glob::glob()``. For a recursive pattern rooted at a symlink, glob
    expansion does not return the symlink root itself, so fact never
    calls ``scan_symlink()`` for the configured root and never associates
    the target directory inode with the configured logical path. Without
    the target directory inode, fact cannot recognise the creation of a
    direct child under the configured path, and the event is dropped
    inside fact before it can be forwarded.

    This mirrors the RHCOS layout:

        <base>/root -> var/roothome   (relative symlink)

    with fact configured to monitor ``<base>/root/**``.
    """
    # Reproduce the RHCOS `/root -> var/roothome` layout: a relative
    # symlink whose target lives beside it.
    base = ignored_dir
    target = os.path.join(base, 'var', 'roothome')
    os.makedirs(target, exist_ok=True)

    symlink = os.path.join(base, 'root')
    os.symlink(os.path.join('var', 'roothome'), symlink)

    # Monitor only the recursive path rooted at the relative symlink,
    # exactly as configured on RHCOS.
    config, config_file = fact_config
    config['paths'] = [f'{symlink}/**']
    reload_config(fact, config, config_file)

    process = Process.from_proc()

    # Create a file directly beneath the symlink root.
    child = os.path.join(symlink, 'direct-child.txt')
    with open(child, 'w') as f:
        f.write('direct child')

    server.wait_events(
        [
            Event(
                process=process,
                event_type=EventType.CREATION,
                # d_path resolves the symlink, so the reported path is
                # the real path under the target directory...
                file=os.path.join(target, 'direct-child.txt'),
                # ...while the host_path reflects the configured logical
                # path through the symlink.
                host_path=child,
            )
        ]
    )
