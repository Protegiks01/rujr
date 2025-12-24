from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


import json
import os


def merge_validated_into_collections():
    """
    Merges all data from reversed_collections.json into collections.json.
    Avoids duplicates based on URL or question field.
    """
    try:
        # Load collections.json
        collections_data = []
        if os.path.exists("collections.json"):
            with open("collections.json", "r") as f:
                collections_data = json.load(f)

        # Load reversed_collections.json
        if not os.path.exists("reversed_collections.json"):
            print("No reversed_collections.json found")
            return

        with open("reversed_collections.json", "r") as f:
            validated_data = json.load(f)

        # Create a set of existing identifiers to avoid duplicates
        existing_identifiers = set()
        for item in collections_data:
            # Use URL or question as identifier
            identifier = item.get("url") or item.get("question") or item.get("filename")
            if identifier:
                existing_identifiers.add(identifier)

        # Merge validated data
        added_count = 0
        for item in validated_data:
            identifier = item.get("url") or item.get("question") or item.get("filename")

            if identifier and identifier not in existing_identifiers:
                collections_data.append(item)
                existing_identifiers.add(identifier)
                added_count += 1

        # Write back to collections.json
        with open("collections.json", "w") as f:
            json.dump(collections_data, f, indent=2)

        print(f"Successfully merged {added_count} items from reversed_collections.json into collections.json")
        print(f"Total items in collections.json: {len(collections_data)}")

    except Exception as e:
        print(f"Error merging files: {e}")


if __name__ == '__main__':
    merge_validated_into_collections()