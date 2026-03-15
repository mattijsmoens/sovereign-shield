"""
Import pre-trained rules into AdaptiveShield database.

Usage:
    python -m sovereign_shield.import_rules [path/to/trained_rules.json]

If no path is given, looks for trained_rules.json next to this module.
"""
import os
import sys


def main():
    from .adaptive import AdaptiveShield

    # Find the JSON file
    if len(sys.argv) > 1:
        json_path = sys.argv[1]
    else:
        json_path = os.path.join(os.path.dirname(__file__), "trained_rules.json")

    if not os.path.exists(json_path):
        print(f"ERROR: {json_path} not found.")
        print(f"Usage: python -m sovereign_shield.import_rules [path/to/trained_rules.json]")
        sys.exit(1)

    # Determine DB path
    db_path = os.path.join("data", "adaptive.db")
    if len(sys.argv) > 2:
        db_path = sys.argv[2]

    print(f"Importing: {json_path}")
    print(f"Database:  {db_path}")

    ada = AdaptiveShield(db_path=db_path)
    ada.import_rules_json(json_path)

    # Reload to show counts
    ada._category_keywords = {}
    ada._load_category_keywords()
    ada._custom_rules = set()
    ada._load_approved_rules()

    total_kw = sum(len(v) for v in ada._category_keywords.items())
    print(f"\nLoaded: {len(ada._custom_rules):,} rules, "
          f"{sum(len(v) for v in ada._category_keywords.values()):,} keywords "
          f"across {len(ada._category_keywords)} categories")
    print("Done.")


if __name__ == "__main__":
    main()
