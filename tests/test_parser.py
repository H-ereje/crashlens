from crashlens.core.parser import LogParser
from crashlens.core.models import Severity


def test_parse_multiline_traceback():
    raw_log = [
        "2026-11-09 10:00:00 [INFO] Server started on port 8000\n",
        "2026-11-09 10:01:00 [ERROR] Database timeout\n",
        "Traceback (most recent call last):\n",
        '  File "app/main.py", line 12, in index\n',
        "    query_db()\n",
        "TimeoutError: Query took longer than 5000ms\n",
        "2026-11-09 10:02:00 [INFO] Health check ok\n",
    ]

    entries = list(LogParser.parse_stream(raw_log))

    assert len(entries) == 3
    # First is INFO
    assert entries[0].level == Severity.INFO
    # Second is ERROR with stacktrace
    assert entries[1].level == Severity.ERROR
    assert entries[1].stacktrace is not None
    assert "TimeoutError" in entries[1].stacktrace
    assert entries[1].error_type == "TimeoutError"
    # Third is INFO
    assert entries[2].level == Severity.INFO


def test_parse_json_logs():
    json_lines = [
        '{"timestamp": "2026-11-09T10:00:00Z", "level": "error", "message": "Redis connection dropped", "error": "ConnectionResetError"}\n',
        '{"timestamp": "2026-11-09T10:00:01Z", "level": "info", "message": "Worker ready"}\n'
    ]

    entries = list(LogParser.parse_stream(json_lines))
    assert len(entries) == 2
    assert entries[0].level == Severity.ERROR
    assert entries[0].error_type == "ConnectionResetError"
    assert entries[1].level == Severity.INFO
