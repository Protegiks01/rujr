from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


import json
import os
from audit import GetReports


def load_processed_reports():
    """Load the list of URLs that already have reports"""
    audits_dir = "audits"
    if not os.path.exists(audits_dir):
        return set()

    # Get all existing report files
    report_files = [f for f in os.listdir(audits_dir) if f.endswith('.md')]

    # Extract URLs from filenames (assuming format like 'report_hash.md')
    # Or you can track them in collections.json
    processed_urls = set()

    # Better approach: read from collections.json
    if os.path.exists("collections.json"):
        try:
            with open("collections.json", "r") as f:
                data = json.load(f)
                # Get URLs that have reports generated
                for item in data:
                    if item.get("report_generated", False):
                        processed_urls.add(item.get("url", ""))
        except Exception as e:
            print(f"Error loading collections: {e}")

    return processed_urls


def get_pending_urls():
    """Get list of URLs that need reports"""
    if not os.path.exists("collections.json"):
        print("No collections.json found")
        return []

    try:
        with open("collections.json", "r") as f:
            data = json.load(f)

        processed = load_processed_reports()
        pending = []

        for item in data:
            url = item.get("url", "")
            if url and url not in processed:
                pending.append(url)

        return pending
    except Exception as e:
        print(f"Error loading collections: {e}")
        return []


def get_remaining_count():
    """
    Returns the total number of URLs that still need reports generated.

    :return: Number of pending reports
    """
    try:
        if not os.path.exists("collections.json"):
            return 0

        with open("collections.json", "r") as f:
            data = json.load(f)

        processed = load_processed_reports()

        # Count URLs that don't have reports yet
        remaining = sum(1 for item in data if item.get("url", "") and item.get("url", "") not in processed)

        return remaining

    except Exception as e:
        print(f"Error getting remaining count: {e}")
        return 0


def main():
    try:
        pending_urls = get_pending_urls()
        total = len(pending_urls)

        if total == 0:
            print("No pending reports to generate")
        else:
            print(f"Found {total} URLs needing reports")

            counter = 0
            report = GetReports(teardown=True)
            for i, url in enumerate(pending_urls):
                print(f"[{i + 1}/{total}] Generating report for: {url[:50]}...")
                report.get_report(url)
                counter += 1
                if counter >= 500:
                    break

            print(f"\n=== Completed {total} reports ===")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == '__main__':
    main()
