import os
import json
import requests

# ------------------------------------------------------------
# 🔐 Configuration: Set your Serper.dev API key here
# ------------------------------------------------------------
SERPER_API_KEY = "sample api key"  # <-- Replace with your actual key
HEADERS = {"X-API-KEY": SERPER_API_KEY}
SEARCH_URL = "https://google.serper.dev/search"

# 🔍 Directory containing 1 JSON file per tool
ROOT_DIR = "MEAindiv"

# ------------------------------------------------------------
# 🧠 Build a targeted GitHub search query using tool + speaker
# ------------------------------------------------------------
def build_query(tool_data):
    tool = tool_data.get("Tool Name", "")
    speakers_raw = tool_data.get("Speakers", [])
    authors = " ".join(speakers_raw if isinstance(speakers_raw, list) else [str(speakers_raw)])
    return f"{tool} github {authors} site:github.com"

# ------------------------------------------------------------
# ✅ Check if a GitHub URL is accessible (status < 400)
# ------------------------------------------------------------
def url_exists(url):
    try:
        response = requests.head(url, timeout=10, allow_redirects=True)
        return response.status_code < 400
    except Exception as e:
        print(f"⚠️ HEAD check failed for {url}: {e}")
        return False

# ------------------------------------------------------------
# 🔎 Search GitHub using Serper and return first valid repo link
# ------------------------------------------------------------
def find_github_repo(tool_data):
    query = build_query(tool_data)
    try:
        response = requests.post(SEARCH_URL, headers=HEADERS, json={"q": query})
        if response.status_code != 200:
            print(f"❌ Serper error {response.status_code} for {tool_data.get('Tool Name')}")
            return None

        results = response.json().get("organic", [])
        for result in results:
            url = result.get("link", "")
            if (
                "github.com" in url
                and "/issues" not in url
                and "/pull" not in url
                and url_exists(url)
            ):
                return url

    except Exception as e:
        print(f"❌ Search failed for {tool_data.get('Tool Name')}: {e}")

    return None

# ------------------------------------------------------------
# 🔄 Main Loop: Walk all JSONs and update missing GitHub URLs
# ------------------------------------------------------------
for dirpath, _, filenames in os.walk(ROOT_DIR):
    for filename in filenames:
        if not filename.endswith(".json"):
            continue

        file_path = os.path.join(dirpath, filename)
        print(f"📄 Processing: {filename}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            print(f"❌ Invalid JSON: {file_path}")
            continue

        is_list = isinstance(data, list)
        tools = data if is_list else [data]
        updated = False

        for tool in tools:
            if tool.get("Github URL"):
                print(f"⏩ Skipping {tool.get('Tool Name')} (already has GitHub URL)")
                continue

            print(f"🔍 Searching GitHub for: {tool.get('Tool Name')}")
            github_url = find_github_repo(tool)

            if github_url:
                tool["Github URL"] = github_url
                updated = True
                print(f"✅ Found and updated: {github_url}")
            else:
                print(f"❌ No valid GitHub URL found for {tool.get('Tool Name')}")

        # 💾 Save back only if new URL was added
        if updated:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(tools if is_list else tools[0], f, indent=2)
