import os
import shutil
import re

# ------------------------------------------------------------
# 🧹 Remove leading number-based prefixes from filenames
# e.g., "0001_0002_mytool.json" → "mytool.json"
# ------------------------------------------------------------
def remove_numbers_prefix(name):
    return re.sub(r'^\d+(_\d+)*_', '', name)

# ------------------------------------------------------------
# 🧰 Flatten a nested folder of JSON files into a single flat directory
# - input_root: parent folder containing subfolders with JSON files
# - output_folder: where cleaned & renamed files will be saved
# ------------------------------------------------------------
def flatten_tool_folders(input_root, output_folder):
    count = 0
    os.makedirs(output_folder, exist_ok=True)

    # Iterate through each subfolder in the root input folder
    for folder_name in sorted(os.listdir(input_root)):
        folder_path = os.path.join(input_root, folder_name)

        # Skip non-folders or output folder itself
        if not os.path.isdir(folder_path) or folder_name == os.path.basename(output_folder):
            continue

        # Iterate through each JSON file in the subfolder
        for file_name in sorted(os.listdir(folder_path)):
            if file_name.endswith(".json"):
                src_path = os.path.join(folder_path, file_name)

                # Clean the filename and prepare destination path
                cleaned_name = remove_numbers_prefix(file_name)
                dst_path = os.path.join(output_folder, cleaned_name)

                # Copy file to destination
                shutil.copy2(src_path, dst_path)
                count += 1
                print(f"✅ {src_path} → {dst_path}")

    print(f"\n📦 Done! Cleaned JSON files saved to: {output_folder}")
    return count

# ------------------------------------------------------------
# 🚀 Entry Point
# Customize the input/output paths below as needed
# ------------------------------------------------------------
if __name__ == "__main__":
    input_root = "USA202425"       # Folder with nested directories of tools
    output_folder = "USAremaining" # Final folder with 1 JSON file per tool

    count = flatten_tool_folders(input_root, output_folder)
    print("Total Tools Flattened:", count)
