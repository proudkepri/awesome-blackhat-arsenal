# 🔧 Arsenal Project: Step-by-Step Walkthrough

---

## ✅ Step 1: Install Requirements

### 📀 Install Python

* Download from: [https://www.python.org/downloads](https://www.python.org/downloads)
* During install, **check the box** that says **"Add Python to PATH"**

### 📦 Install Required Python Packages

```bash
pip install -r requirements.txt
```

---

## ✅ Step 2: Set Up the Project Directory

```bash
cd arsenal-project
```

---

## ✅ Step 3: Folder Structure Overview

```
arsenal-project/
├── Data/                  ← Scraped raw JSONs go here
│   └── Asia/
├── Asia/                 ← Individual tool files go here
│   └── 2023/
├── tools/                ← Final output structure by country/year
│   └── Asia/
├── Links/                ← Legacy schedule links
├── NewLinks/             ← Modern schedule links
├── AutoReadme.py
├── CategoryPredictor.py
├── README.md             ← Final output
```

---

## ✅ Step 4: Scrape Black Hat Tools

### 🔹 Modern Schedule (e.g., `can-24`, `us-23`)

Edit and run:

```bash
python scrape_blackhat_schedule.py
```

Ensure `scrape_all_from_txt("NewLinks/Asia.txt")` is correctly pointing to your `.txt` file.

---

## ✅ Step 5: Add Metadata Fields

```bash
python update_metadata_fields.py
```

This adds `"Year"` and `"Country"` to every tool in `Data/Asia/`

---

## ✅ Step 6: Split into Individual Files

```bash
python split_tools_to_individual_files.py
```

Example output: `Asia/2023/0001_ToolName.json`

---

## ✅ Step 7: Predict Tool Categories (Optional)

```bash
python CategoryPredictor.py
```

Predicts the category using Gemini / OpenAI and updates `Asia/2023/*.json`

---

## ✅ Step 8: Flatten Folder into Final Structure

```bash
python flatten_tool_folders.py
```

Takes input like `Asia/2023/*.json` and moves them to:

```
tools/Asia/2023/ToolName.json
```

Automatically removes prefix numbers like `001_`, `002_`

---

## 📆 Sample Folder Flow

### ✅ Initial:

```
Data/Asia/
└── asia-23_arsenal_schedule_index.html.json
```

### ✅ After Metadata Insertion:

```
Data/Asia/asia-23_arsenal_schedule_index.html.json
  └── Each object now has "Year": 2023, "Country": "Asia"
```

### ✅ After Splitting:

```
Asia/2023/0001_ToolName.json
```

### ✅ Final Output:

```
tools/Asia/2023/ToolName.json
```

---

## 📆 Final Result

* `tools/Asia/2023/*.json`
* Each tool is enriched, categorized, and cleaned.
* `README.md` is auto-generated per region.

Run:

```bash
python AutoReadme.py
```

Generates:

* Top-level `README.md`
* Sub-readmes inside `tools/Asia/2023/`

---

## 📄 Summary of Key Scripts

| Script                               | Purpose                         |
| ------------------------------------ | ------------------------------- |
| `scrape_blackhat_schedule.py`        | Scrape tools from modern events |
| `update_metadata_fields.py`          | Add `Year` and `Country` fields |
| `split_tools_to_individual_files.py` | One file per tool               |
| `CategoryPredictor.py`               | Predict tool track/category     |
| `flatten_tool_folders.py`            | Organize and clean filenames    |
| `AutoReadme.py`                      | Generate project readme files   |

