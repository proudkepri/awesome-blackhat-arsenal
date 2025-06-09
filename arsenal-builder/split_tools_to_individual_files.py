import os
import json
import re

# ------------------------------------------------------------
# 🧼 Sanitize filenames: remove invalid characters and truncate
# ------------------------------------------------------------
def sanitize_filename(name, fallback="tool", max_length=50):
    name = re.sub(r'[\\/*?:"<>|]', "_", name)  # Replace invalid filename characters
    return name.strip()[:max_length] or fallback

# ------------------------------------------------------------
# 📦 Split all tool objects from each JSON file into separate files
# ------------------------------------------------------------
def split_folder_to_individual_json_objects(input_folder, output_folder):
    os.makedirs(output_folder, exist_ok=True)
    counter = 0  # For creating unique filenames

    # Loop through every JSON file in the input folder
    for filename in os.listdir(input_folder):
        if not filename.endswith(".json"):
            continue

        filepath = os.path.join(input_folder, filename)

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                tools = data if isinstance(data, list) else [data]

                for tool in tools:
                    # 🧾 Extract only the desired fields
                    filtered = {
                        "Tool Name": tool.get("Tool Name"),
                        "Speakers": tool.get("Speakers"),
                        "Tracks": tool.get("Tracks"),
                        "Event": tool.get("Event"),
                        "Github URL": tool.get("Github URL"),  # ✅ fixed empty key!
                        "Description": tool.get("Description"),
                        "Year": tool.get("Year"),
                        "Location": tool.get("Country")
                    }

                    # 🏷️ Generate a safe filename
                    raw_name = tool.get("Tool Name") or f"tool_{counter}"
                    safe_name = sanitize_filename(raw_name)
                    filename_out = f"{counter:04d}_{safe_name}.json"
                    output_path = os.path.join(output_folder, filename_out)

                    # 💾 Save the individual tool
                    with open(output_path, "w", encoding="utf-8") as out_f:
                        json.dump(filtered, out_f, indent=2, ensure_ascii=False)

                    print(f"✅ Saved: {filename_out}")
                    counter += 1

        except Exception as e:
            print(f"⚠️ Skipped {filename} due to error: {e}")

# ------------------------------------------------------------
# 🚀 Entry point — customize input/output folders below
# ------------------------------------------------------------
if __name__ == "__main__":
    input_folder = r"MEA"        # Folder containing multi-tool JSON files
    output_folder = r"MEAindiv"  # Output folder for individual tool JSONs

    split_folder_to_individual_json_objects(input_folder, output_folder)
