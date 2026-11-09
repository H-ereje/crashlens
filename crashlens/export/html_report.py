import html
from typing import List, Dict, Any
from ..core.models import Incident, Severity


class HTMLReportGenerator:
    """Generates a modern, single-file, interactive HTML report with dark mode."""

    @classmethod
    def generate(cls, incidents: List[Incident], stats: Dict[str, Any], title: str = "CrashLens Incident Report") -> str:
        rows_html = []
        for inc in incidents:
            sev_badge = {
                Severity.CRITICAL: "bg-red-900 text-red-200 border-red-700",
                Severity.ERROR: "bg-rose-900/60 text-rose-200 border-rose-700",
                Severity.WARNING: "bg-amber-900/60 text-amber-200 border-amber-700",
                Severity.INFO: "bg-blue-900/60 text-blue-200 border-blue-700",
                Severity.DEBUG: "bg-gray-800 text-gray-300 border-gray-700",
            }.get(inc.severity, "bg-gray-800 text-gray-300 border-gray-700")

            stack_html = ""
            if inc.sample_stacktrace:
                escaped_stack = html.escape(inc.sample_stacktrace)
                stack_html = f"""
                <details class="mt-3">
                    <summary class="cursor-pointer text-xs font-semibold uppercase tracking-wider text-cyan-400 hover:text-cyan-300">View Stacktrace</summary>
                    <pre class="mt-2 p-3 bg-black/60 rounded text-xs font-mono text-emerald-400 overflow-x-auto border border-gray-800">{escaped_stack}</pre>
                </details>
                """

            diag_html = ""
            if inc.ai_diagnosis:
                escaped_diag = html.escape(inc.ai_diagnosis)
                diag_html = f"""
                <div class="mt-3 p-3 bg-indigo-950/40 rounded border border-indigo-800 text-xs text-indigo-200">
                    <strong class="text-indigo-400 block mb-1">AI Root-Cause Diagnosis:</strong>
                    {escaped_diag}
                </div>
                """

            first_seen_str = inc.first_seen.strftime("%Y-%m-%d %H:%M:%S") if inc.first_seen else "N/A"
            last_seen_str = inc.last_seen.strftime("%Y-%m-%d %H:%M:%S") if inc.last_seen else "N/A"

            rows_html.append(f"""
            <div class="p-5 bg-gray-900 rounded-xl border border-gray-800 hover:border-gray-700 transition shadow-lg">
                <div class="flex flex-wrap items-center justify-between gap-2 mb-2">
                    <div class="flex items-center gap-3">
                        <span class="px-2.5 py-1 text-xs font-bold font-mono rounded border {sev_badge}">{inc.severity.value}</span>
                        <span class="font-mono text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-400 border border-gray-700">#{inc.fingerprint}</span>
                        <span class="text-xs text-gray-400">First: {first_seen_str} | Last: {last_seen_str}</span>
                    </div>
                    <div class="flex items-center gap-2">
                        <span class="text-xs text-gray-400">Occurrences:</span>
                        <span class="px-3 py-1 text-sm font-bold bg-amber-500/20 text-amber-300 rounded-full border border-amber-500/30 font-mono">x{inc.count}</span>
                    </div>
                </div>
                <h3 class="text-base font-semibold text-gray-100 mb-1">{html.escape(inc.title)}</h3>
                <p class="text-xs text-gray-400 font-mono">{html.escape(inc.sample_message[:200])}</p>
                {stack_html}
                {diag_html}
            </div>
            """)

        cards_content = "\n".join(rows_html) if rows_html else "<p class='text-gray-400'>No incidents recorded.</p>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body {{ font-family: 'Inter', sans-serif; }}
        code, pre, .font-mono {{ font-family: 'JetBrains Mono', monospace; }}
    </style>
</head>
<body class="bg-gray-950 text-gray-200 min-h-screen p-6 md:p-12">
    <div class="max-w-6xl mx-auto space-y-8">
        <!-- Header -->
        <header class="flex flex-col md:flex-row md:items-center justify-between pb-6 border-b border-gray-800 gap-4">
            <div>
                <div class="flex items-center gap-2 mb-1">
                    <span class="inline-block w-3 h-3 rounded-full bg-emerald-500 animate-pulse"></span>
                    <h1 class="text-2xl font-bold tracking-tight text-white">CrashLens Report</h1>
                    <span class="text-xs font-mono bg-cyan-950 text-cyan-300 border border-cyan-800 px-2 py-0.5 rounded">v1.0</span>
                </div>
                <p class="text-sm text-gray-400">Automated Log Aggregation, Sentry-style Fingerprinting & AI Triage</p>
            </div>
            <div class="flex gap-4">
                <div class="px-4 py-2 bg-gray-900 border border-gray-800 rounded-lg text-center">
                    <div class="text-xs text-gray-500 uppercase">Lines Scanned</div>
                    <div class="text-xl font-bold font-mono text-cyan-400">{stats.get('total_lines', 0)}</div>
                </div>
                <div class="px-4 py-2 bg-gray-900 border border-gray-800 rounded-lg text-center">
                    <div class="text-xs text-gray-500 uppercase">Total Errors</div>
                    <div class="text-xl font-bold font-mono text-rose-400">{stats.get('total_issues_found', 0)}</div>
                </div>
                <div class="px-4 py-2 bg-gray-900 border border-gray-800 rounded-lg text-center">
                    <div class="text-xs text-gray-500 uppercase">Unique Issues</div>
                    <div class="text-xl font-bold font-mono text-amber-400">{stats.get('unique_incidents', 0)}</div>
                </div>
            </div>
        </header>

        <!-- Incidents List -->
        <section class="space-y-4">
            <h2 class="text-lg font-semibold text-gray-200 flex items-center gap-2">
                <span>Grouped Incidents</span>
                <span class="text-xs font-normal text-gray-400 font-mono">(Clustered by SHA-256 Fingerprint)</span>
            </h2>
            {cards_content}
        </section>

        <!-- Footer -->
        <footer class="pt-8 border-t border-gray-900 text-center text-xs text-gray-500">
            Generated with <a href="https://github.com/H-ereje" class="text-cyan-400 hover:underline">CrashLens</a> &bull; Created by Harold Cartagena
        </footer>
    </div>
</body>
</html>
"""
