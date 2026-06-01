""" config.py version 1.1.0 """
from __future__ import annotations
import re, yaml
from pathlib import Path
from typing import Any, Dict, List
from .errors import ConfigError
from .types import Config, SignatureDef

def load_config(config_path: Path) -> Config:
    try:
        raw = yaml.safe_load(config_path.read_text())
    except Exception as e:
        raise ConfigError(stage='config', code='CONFIG_LOAD_FAILED', message=str(e), details={'config_path': str(config_path)})
    if not isinstance(raw, dict):
        raise ConfigError(stage='config', code='CONFIG_INVALID', message='Config root must be a mapping', details={})
    for key in ('defaults','sources','outputs','signatures'):
        if key not in raw:
            raise ConfigError(stage='config', code='CONFIG_INVALID', message=f'Missing required key: {key}', details={})
    sigs: List[SignatureDef] = []
    compiled: Dict[str, Any] = {}
    for s in raw.get('signatures', []):
        try:
            sig = SignatureDef(
                id=s['id'],
                group=s.get('group',''),
                event_type=s['event_type'],
                severity=s.get('severity','info'),
                confidence_weight=float(s.get('confidence_weight',0.5)),
                manager_only=bool(s.get('manager_only', False)),
                ports=list(s.get('ports', [])),
                rationale=str(s.get('rationale','')),
                patterns=list(s.get('patterns', [])),
                capture=dict(s.get('capture', {}) or {}),
                context=dict(s.get('context', {}) or {}),
            )
        except Exception as e:
            raise ConfigError(stage='config', code='CONFIG_INVALID_SIGNATURE', message=str(e), details={'sig': s})
        try:
            pats=[re.compile(p) for p in sig.patterns]
            caps={k: re.compile(v) for k,v in sig.capture.items()}
        except Exception as e:
            raise ConfigError(stage='config', code='REGEX_COMPILE_FAILED', message=str(e), details={'signature_id': sig.id})
        sigs.append(sig)
        compiled[sig.id]={'patterns':pats,'capture':caps,'sig':sig}
    return Config(raw=raw, defaults=raw['defaults'], sources=raw['sources'], outputs=raw['outputs'], signatures=sigs, compiled=compiled)
