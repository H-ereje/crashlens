import re
import json
from datetime import datetime
from typing import Generator, Optional, Tuple
from .models import LogEntry, Severity


class LogParser:
    """
    High-performance streaming log parser supporting multi-line stacktraces,
    standard syslog/application formats, and JSON-structured logs.
    """

    # Matches common timestamp + log level prefixes
    # e.g., 2026-11-09 14:30:15,123 [ERROR] module: msg
    # or [2026-11-09T14:30:15Z] ERROR: msg
    _LOG_HEADER_REGEX = re.compile(
        r"^(?:\[?(?P<timestamp>\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\]?\s*)?"
        r"(?:\[?(?P<level>DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL|EXCEPTION)\]?[:\s\-]*)?"
        r"(?P<rest>.*)$",
        re.IGNORECASE,
    )

    # Identifiers for stacktrace starts
    _PYTHON_TRACEBACK_START = "Traceback (most recent call last):"
    _JAVA_NODE_STACK_REGEX = re.compile(r"^\s+at\s+[\w\$./]+", re.IGNORECASE)

    # Identifiers for common exception lines
    _EXCEPTION_LINE_REGEX = re.compile(
        r"^(?P<error_type>[\w\.]*(?:Error|Exception|Fault|Failure|Crash|Panic)):\s*(?P<msg>.*)$"
    )

    # Identifiers for source file and line in python tracebacks
    _PY_FRAME_REGEX = re.compile(r'File "(?P<file>[^"]+)", line (?P<line>\d+), in (?P<func>\w+)')

    @classmethod
    def _parse_timestamp(cls, ts_str: Optional[str]) -> Optional[datetime]:
        if not ts_str:
            return None
        clean_ts = ts_str.replace("T", " ").replace("/", "-").split(".")[0].split(",")[0]
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(clean_ts, fmt)
            except ValueError:
                continue
        return None

    @classmethod
    def parse_stream(cls, lines_iterable) -> Generator[LogEntry, None, None]:
        """
        Processes lines and yields structured LogEntries, automatically assembling
        multi-line stack traces with their parent log line.
        """
        current_entry: Optional[LogEntry] = None
        stacktrace_buffer = []

        for line_num, raw_line in enumerate(lines_iterable, start=1):
            line_str = raw_line.rstrip("\r\n")

            # Check if this line is a JSON log
            stripped = line_str.strip()
            if stripped.startswith("{") and stripped.endswith("}"):
                try:
                    data = json.loads(stripped)
                    # Flush previous entry if any
                    if current_entry:
                        if stacktrace_buffer:
                            current_entry.stacktrace = "\n".join(stacktrace_buffer)
                        yield current_entry
                        current_entry = None
                        stacktrace_buffer = []

                    lvl = Severity.from_str(str(data.get("level") or data.get("severity") or "INFO"))
                    msg = str(data.get("message") or data.get("msg") or stripped)
                    err_type = data.get("error") or data.get("exception_type")
                    stack = data.get("stacktrace") or data.get("stack")

                    yield LogEntry(
                        raw_text=line_str,
                        line_number=line_num,
                        level=lvl,
                        message=msg,
                        error_type=str(err_type) if err_type else None,
                        stacktrace=str(stack) if stack else None,
                        extra=data,
                    )
                    continue
                except json.JSONDecodeError:
                    pass

            # Check if this line is continuation of a stacktrace
            is_stack_line = (
                cls._PYTHON_TRACEBACK_START in line_str
                or cls._JAVA_NODE_STACK_REGEX.match(line_str)
                or (line_str.startswith("  ") and current_entry is not None and current_entry.level in (Severity.ERROR, Severity.CRITICAL))
            )

            if is_stack_line:
                stacktrace_buffer.append(line_str)
                # Try to extract affected file/line if available
                py_match = cls._PY_FRAME_REGEX.search(line_str)
                if py_match and current_entry:
                    current_entry.file_source = py_match.group("file")
                    current_entry.extra["line_number"] = int(py_match.group("line"))
                continue

            # Check for exception definition line at end of traceback: e.g. "ValueError: invalid literal"
            exc_match = cls._EXCEPTION_LINE_REGEX.match(stripped)
            if exc_match and current_entry and stacktrace_buffer:
                stacktrace_buffer.append(line_str)
                current_entry.error_type = exc_match.group("error_type")
                current_entry.message = exc_match.group("msg") or current_entry.message
                continue

            # New standard log line
            match = cls._LOG_HEADER_REGEX.match(line_str)
            if match and (match.group("level") or match.group("timestamp")):
                # Flush previous entry
                if current_entry:
                    if stacktrace_buffer:
                        current_entry.stacktrace = "\n".join(stacktrace_buffer)
                    yield current_entry
                    stacktrace_buffer = []

                level_str = match.group("level") or "INFO"
                severity = Severity.from_str(level_str)
                rest = (match.group("rest") or "").strip()
                ts = cls._parse_timestamp(match.group("timestamp"))

                # Try to extract error type from message if present
                err_type = None
                exc_in_msg = cls._EXCEPTION_LINE_REGEX.match(rest)
                if exc_in_msg:
                    err_type = exc_in_msg.group("error_type")
                    msg_body = exc_in_msg.group("msg")
                else:
                    msg_body = rest

                current_entry = LogEntry(
                    raw_text=line_str,
                    line_number=line_num,
                    timestamp=ts,
                    level=severity,
                    message=msg_body or rest,
                    error_type=err_type,
                )
            else:
                # If it's a random unformatted line, attach to previous or create fallback
                if current_entry:
                    stacktrace_buffer.append(line_str)
                else:
                    current_entry = LogEntry(
                        raw_text=line_str,
                        line_number=line_num,
                        level=Severity.INFO,
                        message=line_str,
                    )

        # Flush final entry
        if current_entry:
            if stacktrace_buffer:
                current_entry.stacktrace = "\n".join(stacktrace_buffer)
            yield current_entry
