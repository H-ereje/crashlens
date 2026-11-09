from crashlens.core.fingerprint import Fingerprinter


def test_fingerprint_normalization_timestamps():
    # Two errors occurring at different timestamps and different IPs
    msg1 = "Connection failed to 192.168.1.50:5432 at 2026-11-09T10:15:30Z"
    msg2 = "Connection failed to 10.0.0.12:5432 at 2026-11-09T11:45:12Z"

    fp1 = Fingerprinter.compute_fingerprint("ConnectionError", msg1)
    fp2 = Fingerprinter.compute_fingerprint("ConnectionError", msg2)

    # They should produce the exact same fingerprint!
    assert fp1 == fp2, f"Fingerprints should match despite different IPs and timestamps: {fp1} != {fp2}"


def test_fingerprint_normalization_hex_addresses():
    # Errors with volatile memory addresses
    msg1 = "Segmentation fault at memory address 0x7fff5fbff8a0"
    msg2 = "Segmentation fault at memory address 0x7ffee1234560"

    fp1 = Fingerprinter.compute_fingerprint("MemoryError", msg1)
    fp2 = Fingerprinter.compute_fingerprint("MemoryError", msg2)

    assert fp1 == fp2


def test_fingerprint_with_stacktrace():
    trace1 = """Traceback (most recent call last):
  File "app/services/users.py", line 45, in get_user
    return db.query(User).filter_by(id=12).first()
AttributeError: 'NoneType' object has no attribute 'first'"""

    trace2 = """Traceback (most recent call last):
  File "app/services/users.py", line 45, in get_user
    return db.query(User).filter_by(id=99).first()
AttributeError: 'NoneType' object has no attribute 'first'"""

    fp1 = Fingerprinter.compute_fingerprint("AttributeError", "NoneType has no attribute first", stacktrace=trace1, affected_file="users.py")
    fp2 = Fingerprinter.compute_fingerprint("AttributeError", "NoneType has no attribute first", stacktrace=trace2, affected_file="users.py")

    assert fp1 == fp2
