"""
Import rules into AdaptiveShield database from a JSON file.

Usage:
    python -m sovereign_shield.import_rules path/to/rules.json [db_path]

The JSON file should have format: {"category_keywords": {...}, "approved_rules": [...]}
"""
import os
import sys


def main():
    from .adaptive import AdaptiveShield

    if len(sys.argv) < 2:
        print("Usage: python -m sovereign_shield.import_rules <rules.json> [db_path]")
        sys.exit(1)

    json_path = sys.argv[1]

    if not os.path.exists(json_path):
        print(f"ERROR: {json_path} not found.")
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

    print(f"\nLoaded: {len(ada._custom_rules):,} rules, "
          f"{sum(len(v) for v in ada._category_keywords.values()):,} keywords "
          f"across {len(ada._category_keywords)} categories")
    print("Done.")


if __name__ == "__main__":
    main()
