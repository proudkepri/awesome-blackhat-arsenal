import os
import json
import re

# ------------------------------------------------------------
# 🌍 Map each folder to (region_code_prefix, readable_region_name)
# Used to determine file matching and metadata insertion
# ------------------------------------------------------------
region_map = {
    "Europe": ("eu", "Europe"),
    "USA": ("us", "USA"),
    "Asia": ("asia", "Asia"),
    "Canada": ("sector", "Canada")
}

# ------------------------------------------------------------
# 📁 Set your working directory here (must match a region_map key)
# ------------------------------------------------------------
folder_path = "Canada"  # Change this to "Europe", "USA", etc. as needed

# Validate folder
if folder_path not in region_map:
    raise ValueError(f"❌ Unknown region folder: {folder_path}")

# Extract matching region details
region_code, region_name = region_map[folder_path]

# ------------------------------------------------------------
# 🔍 Pattern: Matches filenames like 'sector-13_arsenal_schedule_index.html.json'
# Extracts the year component (e.g., 13 → 2013)
# ------------------------------------------------------------
pattern = re.compile(rf'{region_code}-(\d{{4}})_arsenal_schedule_index\.html\.json', re.IGNORECASE)

# ------------------------------------------------------------
# 🔄 Loop through each file in the selected folder
# ------------------------------------------------------------
for filename in os.listdir(folder_path):
    match = pattern.match(filename)
    if not match:
        continue

    # Extract and format full year
    year_suffix = match.group(1)
    full_year = f"20{year_suffix}"
    file_path = os.path.join(folder_path, filename)

    # 📥 Load the JSON content
    with open(file_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print(f"❌ Skipping invalid JSON: {filename}")
            continue

    # 🧾 Add metadata fields to each tool
    for obj in data:
        obj["Year"] = full_year
        obj["Country"] = region_name

    # 💾 Write updated JSON back to the file
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(f"✅ Updated {filename} → Year: {full_year}, Country: {region_name}")
