"""
integrity_check.py — Script integrity verification for py-workedtask.

How to use
----------
1. Generate the expected SHA-256 of your script:

       python integrity_check.py --hash <your_script.py>

   or on Unix/macOS:

       sha256sum <your_script.py>
   on Windows (PowerShell):
       Get-FileHash <your_script.py> -Algorithm SHA256

2. Export the digest as an environment variable before launching:

       # Linux / macOS
       export JAVELIN_EXPECTED_SHA256="<hex-digest>"

       # Windows (cmd)
       set JAVELIN_EXPECTED_SHA256=<hex-digest>

       # Windows (PowerShell)
       $env:JAVELIN_EXPECTED_SHA256="<hex-digest>"

3. The guard will raise SystemExit(1) if the running file's digest does
   not match the value stored in JAVELIN_EXPECTED_SHA256.  When the env
   var is not set the check is skipped (opt-in behaviour).
"""

import hashlib
import os
import sys


def compute_sha256(filepath: str) -> str:
    """Return the lowercase hex SHA-256 digest of *filepath*."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def verify_script_integrity(script_path: str | None = None) -> None:
    """Compare the SHA-256 of *script_path* against ``JAVELIN_EXPECTED_SHA256``.

    Parameters
    ----------
    script_path:
        Path to the script that should be verified.  Defaults to
        ``__file__`` of the *caller* (i.e. the entry-point script).
        Pass an explicit path when calling from a package or when
        ``__file__`` is not the file you want to protect.

    Raises
    ------
    SystemExit(1)
        When the environment variable is set **and** the digest does not
        match, the process exits immediately with a non-zero code so that
        any surrounding process supervisor can detect tampering.
    """
    expected = os.environ.get("JAVELIN_EXPECTED_SHA256", "").strip().lower()
    if not expected:
        # Env var not configured — integrity check is opt-in, skip silently.
        return

    target = script_path or _caller_file()
    if target is None:
        print(
            "[integrity] WARNING: cannot determine script path; "
            "integrity check skipped.",
            file=sys.stderr,
        )
        return

    actual = compute_sha256(target)

    if actual != expected:
        print(
            f"[integrity] FATAL: hash mismatch for '{target}'.\n"
            f"  expected : {expected}\n"
            f"  actual   : {actual}\n"
            "The script may have been tampered with. Aborting.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Hashes match — proceed normally (silent success).


def _caller_file() -> str | None:
    """Walk the call stack to find the outermost ``__file__``."""
    import inspect

    for frame_info in reversed(inspect.stack()):
        filename = frame_info.filename
        if filename and not filename.startswith("<"):
            return os.path.abspath(filename)
    return None


# ---------------------------------------------------------------------------
# CLI helper — run as `python integrity_check.py --hash <file>`
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--hash":
        target_file = sys.argv[2]
        try:
            digest = compute_sha256(target_file)
            print(digest)
        except FileNotFoundError:
            print(f"Error: file not found: {target_file}", file=sys.stderr)
            sys.exit(1)
    elif len(sys.argv) == 2 and sys.argv[1] in ("-h", "--help"):
        print(__doc__)
    else:
        # Self-check demo
        digest = compute_sha256(__file__)
        print(f"SHA-256 of this file ({__file__}):\n  {digest}")
        print(
            "\nTo protect your script set:\n"
            f"  export JAVELIN_EXPECTED_SHA256={digest}"
        )
