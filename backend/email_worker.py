"""Email monitoring worker entrypoint.

Run this as a standalone Render Background Worker:

    python email_worker.py

It reloads active EmailMonitoringConfig rows from the database on startup and
keeps polling the configured mailboxes, updating heartbeats / connection
status / counters as it goes. Safe to run in addition to the in-process
monitor thread started by the API (dedupe is handled via email_processed_uids).
"""

import sys
import time
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("email_worker")


def main() -> int:
    from app.services.email_monitor_service import email_monitor

    email_monitor._load_configs_from_db()
    email_monitor.start()
    logger.info(
        "email_worker started with %d active config(s)",
        len(email_monitor._configs),
    )
    try:
        while email_monitor.is_running():
            time.sleep(5)
    except KeyboardInterrupt:
        logger.info("email_worker shutting down (KeyboardInterrupt)")
    finally:
        email_monitor.stop()
        logger.info("email_worker stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())