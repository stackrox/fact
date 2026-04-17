import os
import re

import requests


def join_path_with_filename(directory, filename):
    """
    Join a directory path with a filename, handling bytes filenames properly.

    When filename is bytes (e.g., containing invalid UTF-8), converts the
    directory to bytes before joining to avoid mixing str and bytes.

    Args:
        directory: Directory path (str)
        filename: Filename (str or bytes)

    Returns:
        Joined path (str or bytes, matching the filename type)
    """
    if isinstance(filename, bytes):
        return os.path.join(os.fsencode(directory), filename)
    else:
        return os.path.join(directory, filename)


def path_to_string(path):
    """
    Convert a filesystem path to string, replacing invalid UTF-8 with U+FFFD.

    This matches the behavior of Rust's String::from_utf8_lossy() used in
    the fact codebase.

    Args:
        path: Filesystem path (str or bytes)

    Returns:
        String representation with invalid UTF-8 replaced by replacement character
    """
    if isinstance(path, bytes):
        return path.decode('utf-8', errors='replace')
    else:
        return path


def rust_style_quote(s):
    """
    Quote a string in the manner of shlex::try_join() rust function.
    
    Use of python's shlex was considered but has a different quoting
    strategy.
    
    Args:
        s: The string to quote
    """
    if not s:
        return "''"
    if re.search(r'[^a-zA-Z0-9_.:/-]', s):
        # Try to match the behavior of shlex.try_join()
        if '\'' in s and not '"' in s:
            return f'"{s}"'
        escaped = s.replace("'", "\\'")
        return f"'{escaped}'"
    return s


def rust_style_join(args):
    """
    Concatenate arguments after quoting them. Each argument is separated
    by a single space.

    Args:
        args: The string to quote
    """
    return ' '.join(rust_style_quote(arg) for arg in args)


def get_metric_value(fact_config, metric_name, labels=None):
    """
    Query Prometheus metrics endpoint to get the value of a metric.

    Args:
        fact_config: The fact configuration tuple (config dict, config file path).
        metric_name: Name of the metric to query (e.g., "host_scanner_scan").
        labels: Optional dict of label filters (e.g., {"label": "InodeRemoved"}).

    Returns:
        The metric value as a string if found, None otherwise.
    """
    config, _ = fact_config
    response = requests.get(f'http://{config["endpoint"]["address"]}/metrics')
    assert response.status_code == 200

    labels = labels or {}

    for line in response.text.split('\n'):
        if metric_name not in line:
            continue

        # Check if all label filters match
        if all(f'{k}="{v}"' in line for k, v in labels.items()):
            # Format: metric_name{label="value"} 42
            parts = line.split()
            if len(parts) >= 2:
                return parts[-1]

    return None
