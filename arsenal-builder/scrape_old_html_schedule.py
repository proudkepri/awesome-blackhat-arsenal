import os
import json
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# ------------------------------------------------------------
# 🧠 Parse static HTML (old site format) and extract tool data
# ------------------------------------------------------------
def extract_tools_from_old_html(html, event_tag):
    soup = BeautifulSoup(html, "html.parser")
    tools = []

    # Each tool is inside a <div class="span-13"> block
    for div in soup.select("div.span-13"):
        title_tag = div.find("h2")
        if not title_tag:
            continue

        # 🛠 Extract tool name and optional anchor ID
        tool_name = title_tag.get_text(strip=True)
        anchor_id = title_tag.find("a")["href"].strip("#") if title_tag.find("a") else None

        # 📝 Extract description if available
        description_tag = div.find("p")
        description = description_tag.get_text(strip=True) if description_tag else None

        # 🧑‍💻 Extract presenters/speakers from adjacent <div class="span-5 last">
        presenters = []
        presenter_block = div.find_next_sibling("div", class_="span-5 last")

        if presenter_block and "presented by" in presenter_block.get_text().lower():
            for a in presenter_block.find_all("a", href=True):
                if a["href"].startswith("presenters/") or a["href"].startswith("speakers/"):
                    presenters.append(a.get_text(strip=True))

        tools.append({
            "tool_name": tool_name,
            "tool_id": anchor_id,
            "speakers": presenters or None,
            "tracks": None,
            "skill_level": "All",  # Not available in old HTML
            "event": event_tag,
            "session_type": "Arsenal",
            "github_url": None,
            "description": description
        })

    return tools

# ------------------------------------------------------------
# 📛 Safely convert URL into a filename (e.g. "2017_asia.json")
# ------------------------------------------------------------
def safe_filename_from_url(url):
    path_parts = urlparse(url).path.strip("/").split("/")
    year = path_parts[-2] if len(path_parts) >= 2 else "unknown"
    tag = path_parts[-1].replace(".html", "").replace("/", "-")
    return f"{year}_{tag}.json"

# ------------------------------------------------------------
# 🌐 Download HTML, extract tool info, save JSON to disk
# ------------------------------------------------------------
def scrape_and_save(url, save_dir):
    print(f"🌐 Fetching: {url}")
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except Exception as e:
        print(f"❌ Failed to fetch {url}: {e}")
        return

    # 🏷️ Infer year tag for event (e.g., ASIA-18 → BH-ASIA-18)
    year_tag = url.split("/")[-2].upper()
    tools = extract_tools_from_old_html(response.text, f"BH-{year_tag}")

    # 💾 Save to file
    filename = safe_filename_from_url(url)
    os.makedirs(save_dir, exist_ok=True)
    save_path = os.path.join(save_dir, filename)

    with open(save_path, "w", encoding="utf-8") as f:
        json.dump(tools, f, indent=2, ensure_ascii=False)

    print(f"✅ Saved {len(tools)} tools → {save_path}")

# ------------------------------------------------------------
# 🚀 Entry Point — Scrape all URLs from input file
# ------------------------------------------------------------
if __name__ == "__main__":
    input_file = "Links/Europe.txt"     # Contains one URL per line
    output_dir = "Data/Europe"          # Output folder for parsed JSON

    # Read all valid URLs from input file
    with open(input_file, "r") as f:
        urls = [line.strip() for line in f if "arsenal.html" in line]

    # Loop through URLs and process
    for url in urls:
        scrape_and_save(url, output_dir)
