import os
import sys
import time
import mimetypes
import subprocess
import magic
import exifread
import piexif
from PIL import Image
from PIL.PngImagePlugin import PngImageFile
from rich.console import Console
from rich.table import Table
from math import log2
import hashlib  # âœ… NEW: For Hash Generation

console = Console()

FILE_SIGNATURES = {
    b'\x50\x4B\x03\x04': '.zip/.docx/.xlsx/.pptx',
    b'\xFF\xD8\xFF': '.jpg/jpeg',
    b'\x89PNG\r\n\x1a\n': '.png',
    b'%PDF-': '.pdf',
    b'PK\x03\x04': '.zip',
    b'Rar!\x1A\x07\x00': '.rar',
    b'7z\xBC\xAF\x27\x1C': '.7z',
    b'\x25\x21PS-Adobe-': '.ps',
}

def format_time(epoch):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epoch))

def get_basic_metadata(file_path):
    try:
        stat = os.stat(file_path)
        mime = magic.from_file(file_path, mime=True)
        return {
            "File Name": os.path.basename(file_path),
            "Full Path": os.path.abspath(file_path),
            "Size": f"{stat.st_size} bytes",
            "Created On": format_time(stat.st_ctime),
            "Modified On": format_time(stat.st_mtime),
            "Accessed On": format_time(stat.st_atime),
            "Permissions": oct(stat.st_mode)[-3:],
            "MIME Type": mime
        }
    except Exception as e:
        return {"Error": str(e)}

def get_hashes(file_path):
    hashes = {"MD5": "", "SHA1": "", "SHA256": ""}
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            hashes["MD5"] = hashlib.md5(data).hexdigest()
            hashes["SHA1"] = hashlib.sha1(data).hexdigest()
            hashes["SHA256"] = hashlib.sha256(data).hexdigest()
    except Exception as e:
        hashes = {"Error": str(e)}
    return hashes

def get_exif_metadata(file_path):
    meta = {}
    try:
        with open(file_path, 'rb') as f:
            tags = exifread.process_file(f, stop_tag="UNDEF", details=False)
            for tag in tags.keys():
                meta[tag] = str(tags[tag])
    except Exception as e:
        meta["EXIF Error"] = str(e)
    return meta

def get_image_metadata(file_path):
    meta = {}
    try:
        with Image.open(file_path) as img:
            meta["Format"] = img.format
            meta["Mode"] = img.mode
            meta["Size (WxH)"] = f"{img.size[0]}x{img.size[1]}"
            meta["Color Type"] = ', '.join(img.getbands())
            if isinstance(img, PngImageFile):
                meta["Compression"] = "Deflate/Inflate"
                meta["Interlace"] = str(img.info.get("interlace", "Noninterlaced"))
                meta["Filter Method"] = "Adaptive"
            megapixel = round((img.width * img.height) / 1_000_000, 6)
            meta["Megapixels"] = f"{megapixel} MP"
    except Exception as e:
        meta["Image Metadata Error"] = str(e)
    return meta

def get_media_metadata(file_path):
    meta = {}
    try:
        result = subprocess.run(["ffprobe", "-v", "error", "-show_entries",
                                 "format=duration,size,bit_rate", "-of",
                                 "default=noprint_wrappers=1", file_path],
                                capture_output=True, text=True)
        for line in result.stdout.strip().split('\n'):
            key, value = line.strip().split('=')
            meta[key] = value
    except Exception as e:
        meta["ffprobe Error"] = str(e)
    return meta

def calc_entropy(data):
    if not data:
        return 0
    occur = [0] * 256
    for b in data:
        occur[b] += 1
    entropy = -sum((f/len(data)) * log2(f/len(data)) for f in occur if f)
    return round(entropy, 4)

def find_embedded_after_iend(file_path):
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            iend_index = content.find(b'IEND')
            if iend_index != -1 and iend_index + 8 < len(content):
                return content[iend_index + 8:]
    except Exception as e:
        console.log(f"[red]IEND check failed: {e}[/red]")
    return None

def scan_for_known_signatures(data):
    for sig, ext in FILE_SIGNATURES.items():
        if data.startswith(sig):
            return ext
    return None

def extract_embedded_file(data, original_file_path):
    detected_ext = scan_for_known_signatures(data) or ".bin"
    detected_mime = magic.from_buffer(data, mime=True)
    ext = mimetypes.guess_extension(detected_mime) or detected_ext
    save_path = os.path.join(os.path.dirname(original_file_path), f"extracted_hidden_file{ext}")
    try:
        with open(save_path, 'wb') as f:
            f.write(data)
        return save_path, detected_mime, ext
    except Exception as e:
        console.log(f"[red]Failed to extract: {e}[/red]")
        return None, None, None

def analyze_file(file_path):
    console.rule("[bold green]ðŸ“ File Metadata")
    meta = get_basic_metadata(file_path)
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Property")
    table.add_column("Value", overflow="fold")
    for k, v in meta.items():
        table.add_row(k, str(v))
    console.print(table)

    # ðŸ” File Hashes
    console.rule("[bold green]ðŸ” Hash Information")
    hashes = get_hashes(file_path)
    hash_table = Table(show_header=True, header_style="bold red")
    hash_table.add_column("Hash Type")
    hash_table.add_column("Value", overflow="fold")
    for htype, hval in hashes.items():
        hash_table.add_row(htype, hval)
    console.print(hash_table)

    # ðŸ–¼ï¸ Image Metadata
    if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif', '.tiff')):
        console.rule("[bold green]ðŸ–¼ï¸ Image Metadata")
        img_meta = get_image_metadata(file_path)
        exif_meta = get_exif_metadata(file_path)
        img_table = Table(show_header=True, header_style="bold magenta")
        img_table.add_column("Property")
        img_table.add_column("Value", overflow="fold")
        for k, v in {**img_meta, **exif_meta}.items():
            img_table.add_row(k, str(v))
        console.print(img_table)

    # ðŸŽ§ Audio/Video Metadata
    if file_path.lower().endswith(('.mp3', '.mp4', '.mkv', '.wav', '.avi', '.mov')):
        console.rule("[bold green]ðŸŽ§ Audio/Video Metadata")
        media_meta = get_media_metadata(file_path)
        media_table = Table(show_header=True, header_style="bold yellow")
        media_table.add_column("Property")
        media_table.add_column("Value", overflow="fold")
        for k, v in media_meta.items():
            media_table.add_row(k, str(v))
        console.print(media_table)

    # ðŸ” Hidden Files / Entropy
    console.rule("[bold yellow]ðŸ” Hidden File Detection")
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            entropy = calc_entropy(content)
            console.print(f"Entropy of file: [cyan]{entropy}[/cyan]")
            if entropy > 7.5:
                console.print("[yellow]âš ï¸ High entropy detected. File may contain embedded/obfuscated content.[/yellow]")

            embedded = find_embedded_after_iend(file_path)
            if embedded:
                console.print("[yellow]Found data after IEND chunk.[/yellow]")
                extracted_path, mime, ext = extract_embedded_file(embedded, file_path)
                if extracted_path:
                    console.print(f"[green]Extracted to:[/green] {extracted_path} | [blue]{mime}[/blue] ({ext})")
                return

            for sig, ext in FILE_SIGNATURES.items():
                idx = content.find(sig, 1024)
                if idx != -1:
                    embedded = content[idx:]
                    console.print(f"[yellow]Found embedded {ext} at offset {idx}[/yellow]")
                    extracted_path, mime, ext2 = extract_embedded_file(embedded, file_path)
                    if extracted_path:
                        console.print(f"[green]Extracted to:[/green] {extracted_path} | [blue]{mime}[/blue] ({ext2})")
                    return
        console.print("[green]No embedded data found.[/green]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        console.print("[bold red]Usage:[/bold red] python mof.py <file_path>")
        sys.exit(1)
    file_path = sys.argv[1]
    if os.path.isfile(file_path):
        analyze_file(file_path)
    else:
        console.print(f"[red]Invalid file path: {file_path}[/red]")
