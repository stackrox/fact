import os
import re


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
