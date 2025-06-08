

# 🕵️‍♂️ MOF - Meta of File
### A File Forensic & Metadata Extraction Tool by **KatifSec**

---

## 🔍 What is MOF?

MOF is a file forensic and metadata analysis tool that:

- Extracts detailed file metadata (creation time, size, MIME, permissions)
- Retrieves image metadata (format, dimensions, megapixels)
- Calculates file hashes (MD5, SHA256)
- Detects and extracts **hidden embedded files
- Detects hidden data after PNG `IEND` chunks or known file signatures
- Displays all results in a beautifully colored table via `rich`

---

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
pip install -r requirements.txt![Screenshot (214)](https://github.com/user-attachments/assets/fbec6528-d07e-4524-8460-cbd6b712487c)


### 

🧪 Usage
python mof.py <file_path>

Example:
python mof.py suspicious_image.png
