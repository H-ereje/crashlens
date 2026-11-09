from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any


class Severity(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        val = value.upper().strip()
        if val in ("FATAL", "CRITICAL", "PANIC"):
            return cls.CRITICAL
        if val in ("ERROR", "EXCEPTION", "ERR"):
            return cls.ERROR
        if val in ("WARN", "WARNING"):
            return cls.WARNING
        if val in ("INFO", "NOTICE"):
            return cls.INFO
        return cls.DEBUG


@dataclass
class LogEntry:
    raw_text: str
    line_number: int
    timestamp: Optional[datetime] = None
    level: Severity = Severity.INFO
    message: str = ""
    error_type: Optional[str] = None
    stacktrace: Optional[str] = None
    file_source: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Incident:
    fingerprint: str
    title: str
    error_type: str
    severity: Severity
    count: int = 1
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    sample_message: str = ""
    sample_stacktrace: Optional[str] = None
    affected_file: Optional[str] = None
    affected_line: Optional[int] = None
    ai_diagnosis: Optional[str] = None
    suggested_patch: Optional[str] = None

    @property
    def summary(self) -> str:
        return f"[{self.fingerprint}] ({self.severity.value}) {self.title} (x{self.count})"
