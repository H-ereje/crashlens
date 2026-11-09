from typing import Dict, List, Iterable, Optional, Any
from datetime import datetime
from .models import LogEntry, Incident, Severity
from .fingerprint import Fingerprinter


class IncidentAggregator:
    """
    Clusters parsed log entries into unique Incidents based on Sentry-like
    fingerprints, aggregating velocity, frequency, and sample context.
    """

    def __init__(self, min_severity: Severity = Severity.WARNING):
        self.min_severity = min_severity
        self.incidents: Dict[str, Incident] = {}
        self.total_lines_processed: int = 0
        self.total_entries_processed: int = 0
        self.total_errors: int = 0

    def should_aggregate(self, level: Severity) -> bool:
        order = [Severity.DEBUG, Severity.INFO, Severity.WARNING, Severity.ERROR, Severity.CRITICAL]
        return order.index(level) >= order.index(self.min_severity)

    def process_entry(self, entry: LogEntry):
        self.total_entries_processed += 1
        self.total_lines_processed = max(self.total_lines_processed, entry.line_number)

        if not self.should_aggregate(entry.level):
            return

        self.total_errors += 1

        err_type = entry.error_type or (entry.level.value if entry.level else "Error")
        msg = entry.message or entry.raw_text

        # Compute fingerprint
        fp = Fingerprinter.compute_fingerprint(
            error_type=err_type,
            message=msg,
            stacktrace=entry.stacktrace,
            affected_file=entry.file_source,
        )

        if fp in self.incidents:
            inc = self.incidents[fp]
            inc.count += 1
            if entry.timestamp:
                if not inc.first_seen or entry.timestamp < inc.first_seen:
                    inc.first_seen = entry.timestamp
                if not inc.last_seen or entry.timestamp > inc.last_seen:
                    inc.last_seen = entry.timestamp
            # Upgrade severity if higher
            if entry.level == Severity.CRITICAL and inc.severity != Severity.CRITICAL:
                inc.severity = Severity.CRITICAL
            # Keep stacktrace if we didn't have one before
            if not inc.sample_stacktrace and entry.stacktrace:
                inc.sample_stacktrace = entry.stacktrace
        else:
            clean_title = Fingerprinter.normalize_text(msg)[:90] or err_type
            line_no = entry.extra.get("line_number")
            self.incidents[fp] = Incident(
                fingerprint=fp,
                title=f"{err_type}: {clean_title}" if err_type not in clean_title else clean_title,
                error_type=err_type,
                severity=entry.level,
                count=1,
                first_seen=entry.timestamp,
                last_seen=entry.timestamp,
                sample_message=entry.message,
                sample_stacktrace=entry.stacktrace,
                affected_file=entry.file_source,
                affected_line=line_no,
            )

    def ingest(self, entries: Iterable[LogEntry]):
        for e in entries:
            self.process_entry(e)

    def get_incidents(self, sort_by: str = "count") -> List[Incident]:
        """Returns sorted incidents. Options: 'count' or 'severity'."""
        inc_list = list(self.incidents.values())
        if sort_by == "severity":
            order = [Severity.DEBUG, Severity.INFO, Severity.WARNING, Severity.ERROR, Severity.CRITICAL]
            inc_list.sort(key=lambda x: (order.index(x.severity), x.count), reverse=True)
        else:
            inc_list.sort(key=lambda x: x.count, reverse=True)
        return inc_list

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "total_lines": self.total_lines_processed,
            "total_entries": self.total_entries_processed,
            "total_issues_found": self.total_errors,
            "unique_incidents": len(self.incidents),
        }
