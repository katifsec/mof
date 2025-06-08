import os
import sys
import time
import mimetypes
import magic
import hashlib
from PIL import Image
from PIL.PngImagePlugin import PngImageFile
from rich.console import Console
from rich.table import Table

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

def calculate_hashes(file_path):
    hashes = {}
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            hashes["MD5"] = hashlib.md5(data).hexdigest()
            hashes["SHA256"] = hashlib.sha256(data).hexdigest()
    except Exception as e:
        hashes["Error"] = str(e)
    return hashes

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

def find_embedded_after_iend(file_path):
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            iend_index = content.find(b'IEND')
            if iend_index != -1 and iend_index + 8 < len(content):
                embedded_data = content[iend_index + 8:]
                return embedded_data
    except Exception as e:
        console.log(f"[red]Error reading file for IEND check: {e}[/red]")
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
        console.log(f"[red]Failed to save extracted file: {e}[/red]")
        return None, None, None

def analyze_file(file_path):
    console.rule("[bold green]File Metadata[/bold green]")
    meta = get_basic_metadata(file_path)
    hash_data = calculate_hashes(file_path)

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Property")
    table.add_column("Value", overflow="fold")
    for k, v in meta.items():
        table.add_row(k, str(v))
    for k, v in hash_data.items():
        table.add_row(k, str(v))
    console.print(table)

    if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif', '.tiff')):
        console.rule("[bold green]Image Metadata[/bold green]")
        img_meta = get_image_metadata(file_path)
        img_table = Table(show_header=True, header_style="bold magenta")
        img_table.add_column("Property")
        img_table.add_column("Value", overflow="fold")
        for k, v in img_meta.items():
            img_table.add_row(k, str(v))
        console.print(img_table)

    console.rule("[bold yellow]Hidden File Detection[/bold yellow]")
    embedded_data = None

    embedded_data = find_embedded_after_iend(file_path)
    if embedded_data:
        console.print("[yellow]Detected data after PNG IEND chunk.[/yellow]")
        extracted_path, mime, ext = extract_embedded_file(embedded_data, file_path)
        if extracted_path:
            console.print(f"[green]Extracted hidden file to:[/green] {extracted_path}")
            console.print(f"[green]Detected MIME type:[/green] {mime} ({ext})")
        else:
            console.print("[red]Failed to extract hidden file.[/red]")
    else:
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                search_start = 1024
                if len(content) > search_start:
                    for sig, ext in FILE_SIGNATURES.items():
                        index = content.find(sig, search_start)
                        if index != -1:
                            embedded_data = content[index:]
                            console.print(f"[yellow]Found embedded file signature '{ext}' at offset {index}.[/yellow]")
                            extracted_path, mime, ext2 = extract_embedded_file(embedded_data, file_path)
                            if extracted_path:
                                console.print(f"[green]Extracted embedded file to:[/green] {extracted_path}")
                                console.print(f"[green]Detected MIME type:[/green] {mime} ({ext2})")
                            else:
                                console.print("[red]Failed to extract embedded file.[/red]")
                            break
                else:
                    console.print("File too small to scan for embedded data.")
        except Exception as e:
            console.print(f"[red]Error scanning file for embedded signatures: {e}[/red]")

    if not embedded_data:
        console.print("[green]No hidden embedded file detected.[/green]")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        console.print("[bold red]Usage: python script.py <file_path>[/bold red]")
        sys.exit(1)

    file_path = sys.argv[1]
    if os.path.isfile(file_path):
        analyze_file(file_path)
    else:
        console.print(f"[red]Invalid file path: {file_path}[/red]")
