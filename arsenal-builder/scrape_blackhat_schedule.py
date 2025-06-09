import os
import json
import time
from urllib.parse import urlparse

# Selenium automation libraries
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoSuchElementException, TimeoutException

# ------------------------------------------------------------
# 🔍 Utility: Safely get text from an element using its class
# ------------------------------------------------------------
def get_text_by_class(container, cls, prefix=""):
    try:
        return container.find_element(By.CLASS_NAME, cls).text.replace(prefix, "").strip()
    except NoSuchElementException:
        return None

# ------------------------------------------------------------
# 🧠 Extract core metadata from a Black Hat schedule page
# ------------------------------------------------------------
def extract_metadata(driver, url, event_tag):
    print(f"🔎 Visiting {url}")
    driver.get(url)
    time.sleep(5)  # Allow time for JavaScript to render elements

    containers = driver.find_elements(By.CLASS_NAME, "data-container")
    tools = []

    for container in containers:
        try:
            link_elem = container.find_element(By.CLASS_NAME, "sd_link")
            tool_name = link_elem.text.strip()
            tool_id = link_elem.get_attribute("data-id")
        except NoSuchElementException:
            tool_name = ""
            tool_id = None

        # Extract speakers, tracks, and metadata
        speakers = [s.text.strip() for s in container.find_elements(By.CLASS_NAME, "speaker_link") if s.text.strip()]
        track_raw = get_text_by_class(container, "session-track", "Tracks:")
        tracks = [t.strip() for t in track_raw.split(",")] if track_raw else None
        location = get_text_by_class(container, "session-session-room", "Location:")
        skill_level = get_text_by_class(container, "session-session-audience-level", "Skill Level:") or "All"
        session_type = get_text_by_class(container, "session-session-type", "Session Type:")

        tools.append({
            "tool_name": tool_name,
            "tool_id": tool_id,
            "speakers": speakers or None,
            "tracks": tracks,
            # "location": location,  # You can re-enable this if needed
            "skill_level": skill_level,
            "event": event_tag,
            "session_type": session_type,
            "github_url": None,
            "description": None  # To be filled later
        })

    return tools

# ------------------------------------------------------------
# 📝 Enrich tool entries with long-form descriptions (modal)
# ------------------------------------------------------------
def enrich_descriptions(driver, tools):
    for tool in tools:
        tool_id = tool.get("tool_id")
        if not tool_id:
            continue

        try:
            # Simulate click to open the modal dialog
            link_elem = driver.find_element(By.CSS_SELECTOR, f'a[data-id="{tool_id}"]')
            driver.execute_script("arguments[0].click();", link_elem)

            # Wait for the description block to load
            desc_div_id = f"session_desc_{tool_id}"
            WebDriverWait(driver, 5).until(
                EC.presence_of_element_located((By.ID, desc_div_id))
            )
            desc_el = driver.find_element(By.CSS_SELECTOR, f"#{desc_div_id} .description")
            tool["description"] = desc_el.get_attribute("innerText").strip()

        except TimeoutException:
            print(f"❌ Timeout for tool_id: {tool_id}")
            tool["description"] = None
        except Exception as e:
            print(f"⚠️ Error for tool_id: {tool_id} – {e}")
            tool["description"] = None

# ------------------------------------------------------------
# 💾 Converts a URL path into a safe filename for saving JSON
# ------------------------------------------------------------
def get_safe_filename_from_url(url):
    parsed = urlparse(url)
    return parsed.path.strip("/").replace("/", "_") + ".json"

# ------------------------------------------------------------
# 📦 Main function to scrape from a .txt file of schedule URLs
# ------------------------------------------------------------
def scrape_all_from_txt(link_file, save_dir="Data/Asia"):
    os.makedirs(save_dir, exist_ok=True)

    # Read event URLs from the text file (one URL per line)
    with open(link_file, "r") as f:
        urls = [line.strip() for line in f if "/schedule" in line]

    # Headless Chrome setup (no GUI)
    options = Options()
    options.add_argument("--headless")
    driver = webdriver.Chrome(options=options)

    # Loop through each schedule URL
    for url in urls:
        event_year = url.split("/")[-3]  # Extract 'us-23' from the URL
        event_tag = f"BH-{event_year.upper()}"

        tools = extract_metadata(driver, url, event_tag)
        enrich_descriptions(driver, tools)

        filename = get_safe_filename_from_url(url)
        output_path = os.path.join(save_dir, filename)

        # Save results to JSON file
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(tools, f, indent=2, ensure_ascii=False)

        print(f"✅ Saved {len(tools)} tools to: {output_path}")

    driver.quit()

# ------------------------------------------------------------
# 🚀 Entry point: Customize the target .txt file here
# ------------------------------------------------------------
if __name__ == "__main__":
    # Example: points to URLs listed in `NewLinks/Canada.txt`
    scrape_all_from_txt("NewLinks/Asia.txt")
