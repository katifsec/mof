

# 🕵️‍♂️ MOF - Meta of File
### A File Forensic & Metadata Extraction Tool by **KatifSec**

---

## 🔍 What is MOF?

🔍 What is MOF?

MOF (Meta of File) is a powerful command-line Python tool that performs comprehensive forensic analysis of any file. 
It extracts metadata, calculates hashes, detects hidden content, and even attempts to extract embedded files.
Whether it's an image, video, document, or archive — MOF helps you discover the truth inside the file.


- ![MOF Output Demo](https://github.com/katifsec/mof/blob/main/73907d70-6a5d-46ba-beef-66f0e0a72760.png)


## ⚙️ Features

✅ File Metadata  
✅ Image Metadata (JPEG, PNG, etc.)  
✅ MD5 & SHA256 Hash Calculation  
✅ Hidden Embedded File Detection  
✅ Signature-Based File Detection  
✅ Extraction of Hidden Data  
✅ Colorful Rich Output in CLI

---

## 📦 Installation

```bash
git clone https://github.com/katifsec/mof.git
cd mof
pip install -r requirements.txt


### 

🧪 Usage
python mof.py <file_path>

Example:
python mof.py suspicious_image.png
