"""
wake_hana.py
------------
Check if the SAP HANA Cloud CF service is stopped and start it if needed.
Polls every 30 seconds until the instance reports 'running'.

Usage:
    python scripts/wake_hana.py

Requirements:
    - CF CLI installed and logged in (cf login done already)
    - Targeting the correct org/space (cf target)
"""

import json
import re
import subprocess
import sys
from datetime import datetime

SERVICE_NAME = "sap-threat-detector-db"
POLL_INTERVAL = 30  # seconds between status checks
MAX_WAIT_MINUTES = 10
MAX_POLLS = (MAX_WAIT_MINUTES * 60) // POLL_INTERVAL


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def run(cmd: list[str]) -> tuple[int, str]:
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout + result.stderr


def get_status() -> str | None:
    """
    Run `cf service <name>` and extract the status from the output.
    Returns lowercase status string like 'running', 'stopped', 'updating', etc.
    Returns None if the service is not found or output can't be parsed.
    """
    code, output = run(["cf", "service", SERVICE_NAME])
    if code != 0:
        print(f"[{ts()}] ERROR: cf service failed:\n{output.strip()}")
        return None

    # `cf service` output has a line like:
    #   status:    running
    # or
    #   Last Operation
    #   Status: create succeeded
    # We look for the most relevant status lines.
    for line in output.splitlines():
        line_lower = line.lower().strip()
        # "status:    running" / "status:    stopped" pattern
        if re.match(r"status:\s+", line_lower):
            value = re.sub(r"^status:\s+", "", line_lower).strip()
            # Map CF operation statuses to simple lifecycle states
            if "stopped" in value or "stop succeeded" in value:
                return "stopped"
            if "running" in value or "create succeeded" in value or "update succeeded" in value:
                return "running"
            if "progress" in value or "updating" in value or "starting" in value:
                return "starting"
            return value  # return raw value for unknown states

    # Fallback: scan all lines for recognizable keywords
    output_lower = output.lower()
    if "stopped" in output_lower:
        return "stopped"
    if "running" in output_lower:
        return "running"

    print(f"[{ts()}] Could not parse status from cf output:\n{output.strip()}")
    return None


def start_instance() -> bool:
    """Send cf update-service to set serviceStopped=false (start the instance)."""
    payload = json.dumps({"data": {"serviceStopped": False}})
    print(f"[{ts()}] Sending start command: cf update-service {SERVICE_NAME} -c '{payload}'")
    code, output = run(["cf", "update-service", SERVICE_NAME, "-c", payload])
    if code != 0:
        print(f"[{ts()}] ERROR: update-service failed:\n{output.strip()}")
        return False
    print(f"[{ts()}] Start command accepted. Waiting for HANA to come up...")
    return True


def main() -> None:
    print(f"[{ts()}] Checking HANA Cloud service: {SERVICE_NAME}")
    print("-" * 60)

    status = get_status()
    if status is None:
        print("Cannot determine service status. Are you logged in? Run: cf login")
        sys.exit(1)

    print(f"[{ts()}] Current status: {status}")

    if status == "running":
        print(f"[{ts()}] HANA is already running. Nothing to do.")
        sys.exit(0)

    if status == "stopped":
        ok = start_instance()
        if not ok:
            sys.exit(1)
    elif status == "starting":
        print(f"[{ts()}] HANA is already starting. Will wait for it...")
    else:
        print(f"[{ts()}] Unexpected status '{status}'. Attempting start anyway...")
        ok = start_instance()
        if not ok:
            sys.exit(1)

    # Poll until running or timeout
    print("-" * 60)
    import time

    for poll in range(1, MAX_POLLS + 1):
        time.sleep(POLL_INTERVAL)
        status = get_status()
        print(f"[{ts()}] Poll {poll}/{MAX_POLLS} — status: {status}")

        if status == "running":
            print("-" * 60)
            print(f"[{ts()}] HANA Cloud is running.")
            sys.exit(0)

        if status is None:
            print(f"[{ts()}] Could not read status, will retry...")

    print("-" * 60)
    print(f"[{ts()}] Timed out after {MAX_WAIT_MINUTES} minutes. Check SAP BTP cockpit.")
    sys.exit(1)


if __name__ == "__main__":
    main()
