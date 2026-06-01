""" extract.py version 1.1.0 """
from __future__ import annotations
import tarfile, shutil
from pathlib import Path
from .errors import ExtractionError
from .types import ExtractResult

# fast: small set, includes command outputs (incl journalctl) for broad compatibility
DEFAULT_FAST_PREFIXES = [
    'var/log/',
    'sos_commands/logs/journalctl',
    'sos_commands/systemd/systemctl',
    'sos_commands/kernel/dmesg',
    'sos_commands/docker/',
]

# journal: prefer tailed journal text to avoid scanning duplicate huge journalctl outputs
# journal: prefer tailed journal text and a small set of syslog-style files.
# Avoid extracting the entire var/log/ tree, which can contain enormous container logs.
DEFAULT_JOURNAL_PREFIXES = [
    # Journald text exports
    'sos_strings/logs/journalctl',   # *.tailed*

    # Common syslog-style locations (extracted selectively)
    'var/log/messages',
    'var/log/syslog',
    'var/log/daemon.log',
    'var/log/kern.log',
    'var/log/docker',
    'var/log/containerd',
    'var/log/installer/syslog',

    # system state and docker info
    'sos_commands/systemd/systemctl',
    'sos_commands/kernel/dmesg',
    'sos_commands/docker/',
]

def _strip_first_component(p: str) -> str:
    parts = p.split('/', 1)
    return parts[1] if len(parts) == 2 else p

def extract_sosreport(archive_path: Path, extract_dir: Path, keep_extracted: bool, extract_mode: str='fast') -> ExtractResult:

    print(f'archive_path: {archive_path}, extract_dir: {extract_dir}, keep_extracted: {keep_extracted}, extract_mode: {extract_mode}')
    try:
        if extract_dir.exists() and not keep_extracted:
            shutil.rmtree(extract_dir)
        extract_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        raise ExtractionError(stage='extract', code='EXTRACT_DIR_FAILED', message=str(e), details={'extract_dir': str(extract_dir)})
    
    print(f'extracting: {archive_path}')
    try:
        tf = tarfile.open(archive_path, mode='r:*')
    except Exception as e:
        raise ExtractionError(stage='extract', code='ARCHIVE_OPEN_FAILED', message=str(e), details={'archive_path': str(archive_path)})
    print(f'archive extracted to: {extract_dir}')
    try:
        members = tf.getmembers()
        if extract_mode not in ('fast','journal','full'):
            raise ExtractionError(stage='extract', code='EXTRACT_MODE_INVALID', message=f'Invalid extract_mode {extract_mode}', details={})

        prefixes = None
        if extract_mode == 'fast':
            prefixes = DEFAULT_FAST_PREFIXES
        elif extract_mode == 'journal':
            prefixes = DEFAULT_JOURNAL_PREFIXES

        if prefixes is None:  # full
            tf.extractall(path=extract_dir)
        else:
            to_extract=[]
            for m in members:
                rel = _strip_first_component(m.name)
                if any(rel.startswith(p) for p in prefixes):
                    to_extract.append(m)
            tf.extractall(path=extract_dir, members=to_extract)
    except ExtractionError:
        raise
    except Exception as e:
        raise ExtractionError(stage='extract', code='EXTRACT_FAILED', message=str(e), details={'archive_path': str(archive_path)})
    finally:
        tf.close()

    roots=[p for p in extract_dir.iterdir() if p.is_dir()]
    extracted_root = roots[0] if len(roots)==1 else extract_dir

    fmt='unknown'
    p=str(archive_path)
    if p.endswith('.tar.gz') or p.endswith('.tgz'): fmt='tar.gz'
    elif p.endswith('.tar.xz'): fmt='tar.xz'
    elif p.endswith('.tar'): fmt='tar'
    return ExtractResult(extracted_root=extracted_root, status='extracted', archive_format=fmt)
