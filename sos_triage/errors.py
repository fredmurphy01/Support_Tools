""" errors.py version 1.1.0 """
from dataclasses import dataclass, field
from typing import Any, Dict

@dataclass
class SosTriageError(Exception):
    stage: str
    code: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    def __str__(self)->str:
        return f"[{self.stage}] {self.code}: {self.message}"

class ConfigError(SosTriageError): ...
class ExtractionError(SosTriageError): ...
class ScanError(SosTriageError): ...
class WriteError(SosTriageError): ...
