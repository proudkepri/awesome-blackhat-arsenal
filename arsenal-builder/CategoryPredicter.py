import os
import json
from openai import OpenAI
import google.generativeai as genai
from dotenv import load_dotenv

# ---------------------
# 🔐 Load API Keys from .env
# ---------------------
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not OPENAI_API_KEY or not GEMINI_API_KEY:
    raise EnvironmentError("Both OPENAI_API_KEY and GEMINI_API_KEY must be set in .env")

# ---------------------
# 🔧 API Client Configuration
# ---------------------
genai.configure(api_key=GEMINI_API_KEY)
client = OpenAI(api_key=OPENAI_API_KEY)

# ---------------------
# 📂 Configuration
# ---------------------
GEMINI_MODEL = genai.GenerativeModel("gemini-1.5-flash")
OPENAI_MODEL = "gpt-4"  # Alternative: "gpt-3.5-turbo"
ROOT_DIR = "output_by_location"
LOG_FILE = "predictions_log.txt"

CATEGORY_KEYS = [
    "Exploitation and Ethical Hacking", "Malware Offense", "Network Attacks", "Reverse Engineering",
    "OSINT - Open Source Intelligence", "Internet of Things", "Hardware / Embedded", "Code Assessment",
    "Web AppSec", "Vulnerability Assessment", "Smart Grid/Industrial Security",
    "Android, iOS and Mobile Hacking", "Cryptography", "Network Defense", "Malware Defense",
    "Data Forensics/Incident Response", "Arsenal Lab", "Human Factors"
]

# ---------------------
# 🧠 Prompt Generator
# ---------------------
def make_prompt(description: str) -> str:
    return f"""
Given the following tool description, select the best matching track from this list:

{', '.join(CATEGORY_KEYS)}

Return only the track name exactly as written. No comments, no formatting.

Description:
{description}
""".strip()

# ---------------------
# 🤖 Gemini Classifier
# ---------------------
def predict_with_gemini(description: str) -> str | None:
    prompt = make_prompt(description)
    try:
        response = GEMINI_MODEL.generate_content(prompt)
        prediction = response.text.strip()
        return prediction if prediction in CATEGORY_KEYS else None
    except Exception as e:
        print(f"⚠️ Gemini error: {e}")
        return None

# ---------------------
# 🤖 OpenAI Classifier (Fallback)
# ---------------------
def predict_with_openai(description: str) -> str | None:
    prompt = make_prompt(description)
    try:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3
        )
        prediction = response.choices[0].message.content.strip()
        return prediction if prediction in CATEGORY_KEYS else None
    except Exception as e:
        print(f"⚠️ OpenAI error: {e}")
        return None

# ---------------------
# 🔄 Main Auto-Classification Loop
# ---------------------
with open(LOG_FILE, "w", encoding="utf-8") as log:
    log.write("Predicted Tracks:\n\n")

    for dirpath, _, filenames in os.walk(ROOT_DIR):
        for file in filenames:
            if not file.endswith(".json"):
                continue

            file_path = os.path.join(dirpath, file)
            with open(file_path, "r", encoding="utf-8") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    print(f"❌ Skipping invalid JSON: {file_path}")
                    continue

            # Skip if already classified
            if data.get("Tracks") is None and data.get("Description"):
                description = data["Description"]
                predicted = predict_with_gemini(description)

                if not predicted:
                    print(f"🔁 Falling back to OpenAI for {file}")
                    predicted = predict_with_openai(description)

                if predicted:
                    data["Tracks"] = [f"Track: {predicted}"]
                    with open(file_path, "w", encoding="utf-8") as f:
                        json.dump(data, f, indent=2)

                    log.write(f"{data.get('Tool Name', file)} → {predicted}\n")
                    print(f"✅ {file} → {predicted}")
                else:
                    log.write(f"{data.get('Tool Name', file)} → ❌ Unable to classify\n")
                    print(f"❌ {file} → Could not classify")
