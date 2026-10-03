"""
feedback_log.py
This file adds the "feedback log" feature (v4, part 1).

Every time an email is analysed (from the command line or the website),
this saves one short record into a simple CSV file: the date/time, the
score, the risk level, and how many rules were triggered.

Important: this does NOT save the actual email content, sender address,
or subject line, only the numbers. So using the tool never builds up a
pile of other people's email content sitting in a file on your computer,
just your own usage history and stats.

This log is what the trend dashboard (the next v4 feature) reads from.
"""

import csv
import os
from datetime import datetime

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "feedback_log.csv")

LOG_HEADERS = ["timestamp", "score", "risk_level", "flag_count", "source"]


def log_result(result: dict, source: str = "cli"):
    """
    Appends one row to the feedback log CSV.

    `source` is just a short label ("cli" or "web") so you can see later
    which interface was used. If writing to the log fails for any reason
    (e.g. no write permission), this quietly does nothing, it never
    crashes the main tool over a logging problem.
    """
    try:
        file_exists = os.path.isfile(LOG_FILE)
        with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(LOG_HEADERS)
            writer.writerow([
                datetime.now().strftime("%Y-%m-%d %H:%M"),
                result.get("score", 0),
                result.get("risk_level", ""),
                len(result.get("flags", [])),
                source,
            ])
    except Exception:
        pass


def read_log() -> list:
    """
    Reads all rows from the feedback log CSV and returns them as a list
    of dictionaries, oldest first. Returns an empty list if the log
    doesn't exist yet (e.g. the tool has never been run before).
    """
    if not os.path.isfile(LOG_FILE):
        return []

    with open(LOG_FILE, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


def clear_log():
    """Deletes the log file, if it exists. Used to reset your history."""
    if os.path.isfile(LOG_FILE):
        os.remove(LOG_FILE)
