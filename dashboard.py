"""
dashboard.py
This file adds the "trend dashboard" feature (v4, part 2).

It reads the feedback log (feedback_log.csv, built by feedback_log.py)
and turns it into simple summary stats and a chart, so you can see your
own usage over time: how many emails you've checked, how many were
HIGH/MEDIUM/LOW risk, and so on.

If the log is empty (the tool has never been run yet), this returns
empty/zero stats instead of crashing, so the dashboard page always loads.
"""

import os

import matplotlib
matplotlib.use("Agg")  # no GUI needed, just save chart images to a file
import matplotlib.pyplot as plt

from feedback_log import read_log

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
CHART_PATH = os.path.join(STATIC_DIR, "dashboard_chart.png")

RISK_ORDER = ["HIGH RISK", "MEDIUM RISK", "LOW RISK", "NO OBVIOUS SIGNS"]
RISK_COLOURS = {
    "HIGH RISK": "#d93025",
    "MEDIUM RISK": "#e08a00",
    "LOW RISK": "#c9a400",
    "NO OBVIOUS SIGNS": "#1e8e3e",
}


def get_dashboard_stats() -> dict:
    """
    Reads the feedback log and returns summary numbers:
    total checks, average score, and a count per risk level.
    """
    rows = read_log()

    total_checks = len(rows)
    risk_counts = {level: 0 for level in RISK_ORDER}
    scores = []

    for row in rows:
        level = row.get("risk_level", "")
        if level in risk_counts:
            risk_counts[level] += 1
        try:
            scores.append(int(row.get("score", 0)))
        except ValueError:
            pass

    average_score = round(sum(scores) / len(scores), 1) if scores else 0

    return {
        "total_checks": total_checks,
        "average_score": average_score,
        "risk_counts": risk_counts,
        "recent_rows": list(reversed(rows))[:10],  # newest 10 first
    }


def build_chart(risk_counts: dict) -> bool:
    """
    Draws a simple bar chart of how many emails fell into each risk
    level, and saves it as a PNG into the static/ folder so the webpage
    can show it as a normal image.

    Returns True if a chart was created, False if there was no data yet
    (nothing to draw).
    """
    if sum(risk_counts.values()) == 0:
        return False

    labels = RISK_ORDER
    values = [risk_counts[level] for level in labels]
    colours = [RISK_COLOURS[level] for level in labels]

    fig, ax = plt.subplots(figsize=(6, 3.5))
    ax.bar(labels, values, color=colours)
    ax.set_ylabel("Number of emails checked")
    ax.set_title("Your phishing checks, by risk level")
    ax.yaxis.get_major_locator().set_params(integer=True)
    for i, v in enumerate(values):
        ax.text(i, v, str(v), ha="center", va="bottom", fontweight="bold")
    fig.tight_layout()

    os.makedirs(STATIC_DIR, exist_ok=True)
    fig.savefig(CHART_PATH, dpi=120)
    plt.close(fig)
    return True
