""" util.py version 1.1.0 """
from __future__ import annotations
import re, datetime, hashlib

_TIME_Q_RE = re.compile(r'time="(?P<ts>\d{4}-\d{2}-\d{2}T[^" ]+Z)"')
_TIME_EQ_RE = re.compile(r'\btime=(?P<ts>\d{4}-\d{2}-\d{2}T[^\s]+Z)\b')
_RFC3339_ANY = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)')
_SYSLOG_RE = re.compile(r'^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})')

MONS = {m:i for i,m in enumerate(['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'], start=1)}

def utc_now_rfc3339()->str:
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat().replace('+00:00','Z')

def default_run_id()->str:
    return datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')

def truncate_line(s:str, max_len:int)->str:
    if len(s)<=max_len: return s
    return s[:max_len-1] + '…'

def normalize_whitespace(s:str)->str:
    return ' '.join(s.strip().split())

def parse_timestamp_best_effort(line:str):
    m=_TIME_Q_RE.search(line)
    if m: return m.group('ts'), m.group('ts')
    m=_TIME_EQ_RE.search(line)
    if m: return m.group('ts'), m.group('ts')
    m=_RFC3339_ANY.search(line)
    if m: return m.group(1), m.group(1)
    m=_SYSLOG_RE.match(line)
    if m:
        # assume current year if absent
        now=datetime.datetime.utcnow()
        try:
            dt=datetime.datetime(now.year, MONS[m.group('mon')], int(m.group('day')),
                                 int(m.group('h')), int(m.group('m')), int(m.group('s')),
                                 tzinfo=datetime.timezone.utc)
            return dt.isoformat().replace('+00:00','Z'), m.group(0)
        except Exception:
            pass
    return None, None

def sha1_hex(s:str)->str:
    return hashlib.sha1(s.encode('utf-8', errors='ignore')).hexdigest()


def rfc3339_to_dt(ts: str):
    """Parse RFC3339 timestamps with optional fractional seconds (up to 9 digits) ending in Z.

    Returns a timezone-aware datetime in UTC, or None.
    """
    if not ts:
        return None
    s = ts.strip()
    if s.endswith('Z'):
        s2 = s[:-1]
        # Split fractional seconds if present
        if '.' in s2:
            base, frac = s2.split('.', 1)
            # keep only digits
            frac_digits = ''.join(ch for ch in frac if ch.isdigit())
            if frac_digits:
                # truncate/pad to 6 for python
                frac6 = (frac_digits + '000000')[:6]
                s2 = f"{base}.{frac6}+00:00"
            else:
                s2 = base + "+00:00"
        else:
            s2 = s2 + "+00:00"
        try:
            return datetime.datetime.fromisoformat(s2)
        except Exception:
            return None
    # allow explicit offset
    try:
        dt = datetime.datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)
    except Exception:
        return None


_OUTPUT_TAG_DISALLOWED = re.compile(r"[^A-Za-z0-9._-]+")
_OUTPUT_TAG_WS = re.compile(r"\s+")


def sanitize_output_tag(tag: str | None) -> str | None:
    """Sanitize a user-provided output tag for safe filenames.

    Rules:
      - allow only [A-Za-z0-9._-]
      - convert whitespace to '_'
      - replace other disallowed characters with '_'
      - strip leading/trailing '-', '_', '.', and spaces

    Returns the sanitized tag or None if empty/invalid after sanitization.
    """

    if tag is None:
        return None
    t = str(tag).strip()
    if not t:
        return None
    t = _OUTPUT_TAG_WS.sub("_", t)
    t = _OUTPUT_TAG_DISALLOWED.sub("_", t)
    t = t.strip("-_. ")
    return t or None
