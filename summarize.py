import json
from collections import Counter
from pathlib import Path

status = json.loads(Path(".run/status.json").read_text())
print("Dataset collection:", status["checked_at"])
print()
for pack in status["packs"]:
    print(f"- {pack['repo']}: {pack['status']}; {pack['updated_sources']} updated sources")
print()
for name, count in sorted(Counter(s["status"] for s in status["sources"]).items()):
    print(f"- {name}: {count}")
