import json

# Load raw data
with open("./SMAH-CTI.json", "r", encoding="utf-8") as f:
    data = json.load(f)

# Keep only entries where relevant == "yes"
filtered_data = [entry for entry in data if entry.get("relevant") == "yes"]

# Save filtered output
with open("smach_filtered.json", "w", encoding="utf-8") as f:
    json.dump(filtered_data, f, ensure_ascii=False, indent=2)

print(f"Filtered count: {len(filtered_data)} (original: {len(data)})")
