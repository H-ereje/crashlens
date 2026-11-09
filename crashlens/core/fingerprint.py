import re
import hashlib
from typing import Optional


class Fingerprinter:
    """
    Reverse-engineered clustering mechanism inspired by Sentry.
    Normalizes volatile log noise (timestamps, memory addresses, UUIDs, IPs)
    to cluster identical root-cause exceptions under the same fingerprint hash.
    """

    # Compiled regex patterns for normalization
    _UUID_REGEX = re.compile(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    )
    _HEX_ADDR_REGEX = re.compile(r"0x[0-9a-fA-F]{4,16}")
    _IP_PORT_REGEX = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b")
    _ISO_TIMESTAMP_REGEX = re.compile(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    )
    _DATE_LOG_REGEX = re.compile(
        r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b",
        re.IGNORECASE,
    )
    _NUMERIC_ID_REGEX = re.compile(r"\b(?:id|user|order|pid|worker|process)[_=\s:]+(\d+)\b", re.IGNORECASE)

    @classmethod
    def normalize_text(cls, text: str) -> str:
        """Strips volatile runtime signatures from log text."""
        if not text:
            return ""

        # 1. Normalize timestamps
        cleaned = cls._ISO_TIMESTAMP_REGEX.sub("<TIMESTAMP>", text)
        cleaned = cls._DATE_LOG_REGEX.sub("<TIMESTAMP>", cleaned)

        # 2. Normalize memory addresses
        cleaned = cls._HEX_ADDR_REGEX.sub("<HEX_ADDR>", cleaned)

        # 3. Normalize UUIDs and hashes
        cleaned = cls._UUID_REGEX.sub("<UUID>", cleaned)

        # 4. Normalize IPs and ports
        cleaned = cls._IP_PORT_REGEX.sub("<HOST_IP>", cleaned)

        # 5. Normalize dynamic numerical IDs
        cleaned = cls._NUMERIC_ID_REGEX.sub(r"\g<1>=<ID>", cleaned)

        # 6. Collapse extra whitespace
        cleaned = re.sub(r"\s+", " ", cleaned).strip()

        return cleaned

    @classmethod
    def compute_fingerprint(
        cls,
        error_type: str,
        message: str,
        stacktrace: Optional[str] = None,
        affected_file: Optional[str] = None,
    ) -> str:
        """
        Generates a 10-character SHA-256 fingerprint for grouping.
        Combines error type, normalized message, and key stack frames.
        """
        norm_type = (error_type or "UnknownError").strip()
        norm_msg = cls.normalize_text(message)

        components = [norm_type]

        if affected_file:
            # Extract just the filename to be immune to absolute path differences across servers
            clean_file = affected_file.replace("\\", "/").split("/")[-1]
            components.append(clean_file)

        if stacktrace:
            # Extract top 3 caller frames or lines from stacktrace
            frames = []
            for line in stacktrace.splitlines():
                line = line.strip()
                if line.startswith("File ") or line.startswith("at ") or "Exception" in line:
                    frames.append(cls.normalize_text(line))
            components.append("|".join(frames[-4:] if frames else [norm_msg]))
        else:
            components.append(norm_msg[:120])

        signature = "::".join(components)
        digest = hashlib.sha256(signature.encode("utf-8")).hexdigest()
        return digest[:10].upper()
