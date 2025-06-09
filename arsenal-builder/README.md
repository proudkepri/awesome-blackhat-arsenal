

# 🛠️ Full Walkthrough: From Scraping Tools to Publishing an Auto README

---

## ✅ Step 1: Install Requirements

### 📌 Install Python (if you don’t have it)

* Download from: [https://www.python.org/downloads](https://www.python.org/downloads)
* During install, **check the box** that says **“Add Python to PATH”**

### 📦 Install required Python packages

#### Copy and paste this

```bash
pip install -r requirements.txt
```

---

## ✅ Step 2: Set Up the Project Folder

```bash
cd arsenal-project
```

---

## ✅ Step 3: Recommended Folder Structure

```
arsenal-project/
├── Data/
│   └── Canada/
├── CanadaIndiv/
├── CanadaCleaned/
├── tools/
│   └── Canada/
│       └── 2023/
├── Links/
│   ├── Canada.txt
│   └── Europe.txt
├── NewLinks/
│   └── Canada.txt
├── AutoReadme.py         ← final readme generator
├── CategoryPredictor.py  ← LLM-based track classifier
├── run.py                ← one-click execution script
├── README.md             ← auto-generated
```

---

## ✅ Step 4: Sample Input Links

### 🔹 For modern schedule scraper (`scrape_blackhat_schedule.py`)

**NewLinks/Canada.txt**

```
https://www.blackhat.com/can-24/arsenal/schedule/index.html
https://www.blackhat.com/us-23/arsenal/schedule/index.html
```

### 🔹 For legacy HTML scraper (`scrape_old_html_schedule.py`)

**Links/Europe.txt**

```
https://www.blackhat.com/asia-18/arsenal.html
```

---

## ✅ Step-by-Step Manual Commands

### 🔹 1. Scrape Event Pages

Modern (JS-based):

```bash
python scrape_blackhat_schedule.py
```

Legacy (static HTML):

```bash
python scrape_old_html_schedule.py
```

---

### 🔹 2. Add Year and Country to Each Tool

```bash
python update_metadata_fields.py
```

---

### 🔹 3. Split All Tools into Individual Files

```bash
python split_tools_to_individual_files.py
```

---

### 🔹 4. Predict Tool Categories (Tracks)

```bash
python CategoryPredictor.py
```

> Uses GPT or Gemini to infer category from description
> ✅ Adds: `"Tracks": ["Track: Red Teaming"]`

---

### 🔹 5. Add GitHub URLs Using Serper.dev

1. Open `add_github_urls.py` and set your API key:

```python
SERPER_API_KEY = "your-api-key-here"
```

2. Run:

```bash
python add_github_urls.py
```

---

### 🔹 6. Flatten Nested Files and add it to the root folder

```bash
python flatten_tool_folders.py
```

---

### 🔹 7. Generate README Files

```bash
python AutoReadme.py
```

✅ Outputs:

* An organized `README.md` at the root
* Sub-readmes under `tools/Region/Year/`

---

## ✅ Optional: One-Click Execution

Use the bundled automation script to run everything in one command:

```bash
python run.py
```

It will:

* Scrape
* Enrich
* Predict
* Add GitHub URLs
* Flatten
* Generate README

---

## 📦 Final Output

* `README.md` organized by region → year → category
* `tools/{Region}/{Year}/README.md` (sub-lists)
* One JSON file per tool, enriched and categorized

---

## 📝 Script Summary

| Script                               | Purpose                                |
| ------------------------------------ | -------------------------------------- |
| `scrape_blackhat_schedule.py`        | Scrape modern Black Hat pages          |
| `scrape_old_html_schedule.py`        | Scrape legacy static HTML pages        |
| `update_metadata_fields.py`          | Add `"Year"` and `"Country"` fields    |
| `split_tools_to_individual_files.py` | Split tools into one file per tool     |
| `CategoryPredictor.py`               | Predict `"Tracks"` using GPT/Gemini    |
| `add_github_urls.py`                 | Add `"Github URL"` using Serper API    |
| `flatten_tool_folders.py`            | Flatten nested folders                 |
| `AutoReadme.py`                      | Generate README.md files automatically |
| `run.py`                             | 🟢 One-click pipeline to run all steps |

---

