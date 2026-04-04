"""Scheduled Scans module for Andy VulnScanner.

Allows setting up recurring scans with configurable intervals
and optional email notifications.
"""

import json
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional


@dataclass
class ScheduledScan:
    """Represents a scheduled scan configuration."""

    scan_id: str
    target: str
    scan_types: list[str]  # e.g. ["port", "web", "advanced"]
    interval_minutes: int = 60
    enabled: bool = True
    last_run: str = ""
    next_run: str = ""
    run_count: int = 0
    notify_email: str = ""
    created: str = ""


class ScanScheduler:
    """Manage scheduled/recurring vulnerability scans."""

    CONFIG_FILE = os.path.expanduser("~/.andy-vulnscanner-schedules.json")

    def __init__(
        self,
        on_log: Optional[Callable[[str, str], None]] = None,
        on_scan_trigger: Optional[Callable[[ScheduledScan], None]] = None,
    ):
        self.on_log = on_log
        self.on_scan_trigger = on_scan_trigger
        self._schedules: dict[str, ScheduledScan] = {}
        self._timer_threads: dict[str, threading.Timer] = {}
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._load_schedules()

    def _log(self, msg: str, level: str = "info"):
        if self.on_log:
            self.on_log(msg, level)

    # ── Schedule Management ──────────────────────────────────────────

    def add_schedule(
        self,
        target: str,
        scan_types: list[str],
        interval_minutes: int = 60,
        notify_email: str = "",
    ) -> ScheduledScan:
        """Add a new scheduled scan."""
        scan_id = f"sched_{int(time.time())}_{len(self._schedules)}"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        schedule = ScheduledScan(
            scan_id=scan_id,
            target=target,
            scan_types=scan_types,
            interval_minutes=interval_minutes,
            enabled=True,
            created=now,
            next_run=now,
            notify_email=notify_email,
        )

        with self._lock:
            self._schedules[scan_id] = schedule

        self._save_schedules()
        self._log(
            f"  Schedule added: {scan_id} -> {target} "
            f"every {interval_minutes}min", "success",
        )
        return schedule

    def remove_schedule(self, scan_id: str) -> bool:
        """Remove a scheduled scan."""
        with self._lock:
            if scan_id in self._schedules:
                del self._schedules[scan_id]
                # Cancel timer if running
                if scan_id in self._timer_threads:
                    self._timer_threads[scan_id].cancel()
                    del self._timer_threads[scan_id]
                self._save_schedules()
                self._log(f"  Schedule removed: {scan_id}", "info")
                return True
        return False

    def toggle_schedule(self, scan_id: str) -> bool:
        """Toggle a schedule on/off. Returns new state."""
        with self._lock:
            if scan_id in self._schedules:
                sched = self._schedules[scan_id]
                sched.enabled = not sched.enabled
                self._save_schedules()
                state = "enabled" if sched.enabled else "disabled"
                self._log(f"  Schedule {scan_id}: {state}", "info")
                return sched.enabled
        return False

    def get_schedules(self) -> list[ScheduledScan]:
        """Get all scheduled scans."""
        with self._lock:
            return list(self._schedules.values())

    def get_schedule(self, scan_id: str) -> Optional[ScheduledScan]:
        """Get a specific schedule."""
        with self._lock:
            return self._schedules.get(scan_id)

    # ── Scheduler Engine ─────────────────────────────────────────────

    def start(self):
        """Start the scheduler engine."""
        self._stop_event.clear()
        self._log("  Scheduler engine started.", "success")

        # Start timers for all enabled schedules
        with self._lock:
            for scan_id, sched in self._schedules.items():
                if sched.enabled:
                    self._start_timer(scan_id)

    def stop(self):
        """Stop the scheduler engine."""
        self._stop_event.set()
        # Cancel all timers
        with self._lock:
            for timer in self._timer_threads.values():
                timer.cancel()
            self._timer_threads.clear()
        self._log("  Scheduler engine stopped.", "info")

    def _start_timer(self, scan_id: str):
        """Start a timer for a scheduled scan."""
        if self._stop_event.is_set():
            return

        sched = self._schedules.get(scan_id)
        if not sched or not sched.enabled:
            return

        # Cancel existing timer
        if scan_id in self._timer_threads:
            self._timer_threads[scan_id].cancel()

        interval_seconds = sched.interval_minutes * 60

        def _run():
            if self._stop_event.is_set():
                return
            self._execute_scheduled_scan(scan_id)
            # Reschedule
            if not self._stop_event.is_set():
                self._start_timer(scan_id)

        timer = threading.Timer(interval_seconds, _run)
        timer.daemon = True
        timer.start()
        self._timer_threads[scan_id] = timer

        now = datetime.now()
        from datetime import timedelta
        next_run = now + timedelta(minutes=sched.interval_minutes)
        sched.next_run = next_run.strftime("%Y-%m-%d %H:%M:%S")

    def _execute_scheduled_scan(self, scan_id: str):
        """Execute a scheduled scan."""
        with self._lock:
            sched = self._schedules.get(scan_id)
            if not sched or not sched.enabled:
                return

            sched.last_run = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            sched.run_count += 1

        self._log(
            f"\n  Executing scheduled scan: {scan_id} "
            f"(target: {sched.target})", "header",
        )

        # Trigger the scan callback
        if self.on_scan_trigger:
            self.on_scan_trigger(sched)

        self._save_schedules()

    # ── Persistence ──────────────────────────────────────────────────

    def _save_schedules(self):
        """Save schedules to disk."""
        data = {}
        for scan_id, sched in self._schedules.items():
            data[scan_id] = {
                "scan_id": sched.scan_id,
                "target": sched.target,
                "scan_types": sched.scan_types,
                "interval_minutes": sched.interval_minutes,
                "enabled": sched.enabled,
                "last_run": sched.last_run,
                "next_run": sched.next_run,
                "run_count": sched.run_count,
                "notify_email": sched.notify_email,
                "created": sched.created,
            }
        try:
            with open(self.CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def _load_schedules(self):
        """Load schedules from disk."""
        if not os.path.exists(self.CONFIG_FILE):
            return
        try:
            with open(self.CONFIG_FILE, encoding="utf-8") as f:
                data = json.load(f)
            for scan_id, info in data.items():
                self._schedules[scan_id] = ScheduledScan(
                    scan_id=info.get("scan_id", scan_id),
                    target=info.get("target", ""),
                    scan_types=info.get("scan_types", []),
                    interval_minutes=info.get("interval_minutes", 60),
                    enabled=info.get("enabled", True),
                    last_run=info.get("last_run", ""),
                    next_run=info.get("next_run", ""),
                    run_count=info.get("run_count", 0),
                    notify_email=info.get("notify_email", ""),
                    created=info.get("created", ""),
                )
        except Exception:
            pass
