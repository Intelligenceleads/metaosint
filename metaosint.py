#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import datetime
import re
import subprocess
from pathlib import Path

# ---------- БИБЛИОТЕКИ ДЛЯ МЕТАДАННЫХ ----------
try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PILLOW_OK = True
except ImportError:
    PILLOW_OK = False

import exifread

# ========== WHOIS (ИСПРАВЛЕНА ОШИБКА С ЧАСОВЫМИ ПОЯСАМИ) ==========
def whois_query(target):
    """
    Получает whois для домена или IP.
    Сначала системная команда, затем python-whois (без вычисления возраста) и ipwhois для IP.
    """
    # Определяем, IP это или домен
    is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target) is not None

    # 1. Пробуем системную команду whois (работает на всех ОС, если утилита установлена)
    try:
        if sys.platform == "win32":
            cmd = ['whois.exe', target]
        else:
            cmd = ['whois', target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode == 0 and result.stdout:
            out = result.stdout.strip()
            if len(out) > 3000:
                out = out[:3000] + "\n... (обрезано)"
            return out
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # 2. Для IP - используем ipwhois (если системный whois не сработал)
    if is_ip:
        try:
            from ipwhois import IPWhois
            obj = IPWhois(target)
            res = obj.lookup_rdap(depth=1)
            output = []
            output.append(f"IP: {target}")
            output.append(f"Страна: {res.get('asn_country_code', '')}")
            output.append(f"ASN: {res.get('asn', '')}")
            output.append(f"Организация: {res.get('network', {}).get('name', '')}")
            return "\n".join(output)
        except ImportError:
            return "Ошибка: для IP-адресов установите 'pip install ipwhois'"
        except Exception as e:
            return f"IP whois ошибка: {e}"

    # 3. Для доменов - python-whois (без вычисления возраста, чтобы избежать ошибок timezone)
    try:
        import whois
        w = whois.whois(target)
        if not w:
            return f"Не удалось получить whois-данные для {target}."
        output = []
        output.append(f"Домен: {target}")
        output.append(f"Регистратор: {w.registrar}")
        if w.creation_date:
            cd = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            output.append(f"Дата регистрации: {cd}")
        if w.expiration_date:
            ed = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            output.append(f"Дата окончания: {ed}")
        if w.name_servers:
            output.append(f"NS: {', '.join(w.name_servers)}")
        return "\n".join(output)
    except ImportError:
        return "Ошибка: не установлен python-whois. Выполните: pip install python-whois"
    except Exception as e:
        return f"Ошибка whois: {e}"

# ========== РАБОТА С ПУТЯМИ ==========
def resolve_path(path_str: str) -> Path:
    path_str = path_str.strip()
    if (path_str.startswith('"') and path_str.endswith('"')) or \
       (path_str.startswith("'") and path_str.endswith("'")):
        path_str = path_str[1:-1]
    if path_str.startswith('~'):
        path_str = os.path.expanduser(path_str)
    return Path(path_str).resolve()

# ========== МЕТАДАННЫЕ ИЗОБРАЖЕНИЙ ==========
def get_gps_coords(exif):
    if not exif:
        return None
    gps_info = {}
    for tag, value in exif.items():
        decoded = TAGS.get(tag, tag)
        if decoded == 'GPSInfo':
            for gps_tag in value:
                sub_decoded = GPSTAGS.get(gps_tag, gps_tag)
                gps_info[sub_decoded] = value[gps_tag]
            break
    if not gps_info:
        return None
    def to_degrees(v):
        return float(v[0]) + float(v[1])/60 + float(v[2])/3600
    lat = gps_info.get('GPSLatitude')
    lon = gps_info.get('GPSLongitude')
    if lat and lon:
        lat_val = to_degrees(lat)
        lon_val = to_degrees(lon)
        if gps_info.get('GPSLatitudeRef') == 'S':
            lat_val = -lat_val
        if gps_info.get('GPSLongitudeRef') == 'W':
            lon_val = -lon_val
        alt = gps_info.get('GPSAltitude')
        alt_val = float(alt) if alt else None
        return {"Широта": lat_val, "Долгота": lon_val, "Высота": alt_val if alt_val is not None else ""}
    return None

def extract_metadata_pillow(filepath):
    img = Image.open(filepath)
    exif = img._getexif() if hasattr(img, '_getexif') else None
    meta = {}
    if exif:
        for tag_id, val in exif.items():
            tag = TAGS.get(tag_id, tag_id)
            if tag in ('Make','Model','DateTimeOriginal','Software','Copyright','Artist',
                       'ImageDescription','ExposureTime','FNumber','ISOSpeedRatings',
                       'FocalLength','Flash','XResolution','YResolution','BitsPerSample'):
                if val:
                    if tag == 'Make': meta["Производитель камеры"] = str(val)
                    elif tag == 'Model': meta["Модель камеры"] = str(val)
                    elif tag == 'DateTimeOriginal': meta["Дата съёмки"] = str(val)
                    elif tag == 'Software': meta["Программа"] = str(val)
                    elif tag == 'Copyright': meta["Авторское право"] = str(val)
                    elif tag == 'Artist': meta["Автор"] = str(val)
                    elif tag == 'ImageDescription': meta["Описание"] = str(val)
                    elif tag == 'ExposureTime': meta["Выдержка"] = str(val)
                    elif tag == 'FNumber': meta["Диафрагма"] = f"f/{val}"
                    elif tag == 'ISOSpeedRatings': meta["Светочувствительность"] = str(val)
                    elif tag == 'FocalLength': meta["Фокусное расстояние"] = f"{val} mm"
                    elif tag == 'Flash': meta["Вспышка"] = "Сработала" if val == 1 else "Не сработала"
                    elif tag == 'XResolution': meta["Горизонтальное разрешение"] = str(val)
                    elif tag == 'YResolution': meta["Вертикальное разрешение"] = str(val)
                    elif tag == 'BitsPerSample': meta["Глубина бит"] = str(val)
    w, h = img.size
    meta["Ширина"] = str(w)
    meta["Высота"] = str(h)
    meta["Размеры"] = f"{w} x {h}"
    meta["Изображение"] = img.format if img.format else Path(filepath).suffix.upper().replace('.', '')
    if "Производитель камеры" in meta or "Модель камеры" in meta:
        meta["Камера"] = f"{meta.get('Производитель камеры', '')} {meta.get('Модель камеры', '')}".strip()
    gps = get_gps_coords(exif)
    if gps:
        meta["GPS"] = gps
    return meta

def extract_metadata_exifread(filepath):
    meta = {}
    with open(filepath, 'rb') as f:
        tags = exifread.process_file(f, details=False)
    if not tags:
        return meta
    mapping = {
        'Image Make': 'Производитель камеры', 'Image Model': 'Модель камеры',
        'EXIF DateTimeOriginal': 'Дата съёмки', 'Image Software': 'Программа',
        'Image Copyright': 'Авторское право', 'Image Artist': 'Автор',
        'Image ImageDescription': 'Описание', 'EXIF ExposureTime': 'Выдержка',
        'EXIF FNumber': 'Диафрагма', 'EXIF ISOSpeedRatings': 'Светочувствительность',
        'EXIF FocalLength': 'Фокусное расстояние', 'EXIF Flash': 'Вспышка',
        'Image XResolution': 'Горизонтальное разрешение', 'Image YResolution': 'Вертикальное разрешение',
        'Image BitsPerSample': 'Глубина бит', 'Image ImageWidth': 'Ширина',
        'Image ImageLength': 'Высота'
    }
    for exif_key, our_key in mapping.items():
        if exif_key in tags:
            val = str(tags[exif_key])
            if our_key == 'Диафрагма':
                val = f"f/{val}"
            elif our_key == 'Вспышка':
                val = "Не сработала" if '0' in val else "Сработала"
            meta[our_key] = val
    if 'Ширина' in meta and 'Высота' in meta:
        meta["Размеры"] = f"{meta['Ширина']} x {meta['Высота']}"
    if 'Производитель камеры' in meta or 'Модель камеры' in meta:
        meta["Камера"] = f"{meta.get('Производитель камеры', '')} {meta.get('Модель камеры', '')}".strip()
    # GPS
    try:
        lat_ref = tags.get('GPS GPSLatitudeRef', 'N')
        lon_ref = tags.get('GPS GPSLongitudeRef', 'E')
        lat = tags.get('GPS GPSLatitude')
        lon = tags.get('GPS GPSLongitude')
        if lat and lon:
            lat_val = float(lat.values[0]) + float(lat.values[1])/60 + float(lat.values[2])/3600
            lon_val = float(lon.values[0]) + float(lon.values[1])/60 + float(lon.values[2])/3600
            if str(lat_ref).strip().upper() == 'S':
                lat_val = -lat_val
            if str(lon_ref).strip().upper() == 'W':
                lon_val = -lon_val
            alt = tags.get('GPS GPSAltitude')
            alt_val = float(alt.values[0]) if alt else None
            meta["GPS"] = {"Широта": lat_val, "Долгота": lon_val, "Высота": alt_val if alt_val is not None else ""}
    except:
        pass
    return meta

def get_metadata(filepath: Path):
    if not filepath.exists():
        return {"Ошибка": f"Файл не найден: {filepath}"}
    if PILLOW_OK:
        try:
            meta = extract_metadata_pillow(filepath)
            if meta:
                return meta
        except:
            pass
    try:
        meta = extract_metadata_exifread(filepath)
        if meta:
            return meta
    except:
        pass
    return {"Сообщение": "Метаданные отсутствуют. Файл не содержит EXIF-информации."}

# ========== КРАСИВЫЙ БАННЕР ==========
def show_banner():
    art = r"""
   ███▄ ▄███▓ ███████ ▄▄▄█████▓ ▄▄▄       ▒█████   ██████ ██▓ ███▄    █ ▄▄▄█████▓
  ▓██▒▀█▀ ██▒ ██      ▓  ██▒ ▓▒▒████▄    ▒██▒  ██▒▒██    ▓███▒ ██ ▀█   █ ▓  ██▒ ▓▒
  ▓██    ▓██░ ██      ▒ ▓██░ ▒░▒██  ▀█▄  ▒██░  ██▒░ ▓██▄ ▒██▒▓██  ▀█ ██▒▒ ▓██░ ▒░
  ▒██    ▒██ ░██     ░ ▓██▓ ░ ░██▄▄▄▄██ ▒██   ██░  ▒   ██░██░▓██▒  ▐▌██▒░ ▓██▓ ░ 
  ▒██▒   ░██▒░███████  ▒██▒ ░  ▓█   ▓██▒░ ████▓▒░▒██████▒▒██░▒██░   ▓██░  ▒██▒ ░ 
  ░ ▒░   ░  ░░ ░░░░░░   ▒ ░░    ▒▒   ▓▒█░░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░░▓  ░ ▒░   ▒ ▒   ▒ ░░ 
   ░  ░      ░           ░       ▒   ▒▒ ░  ░ ▒ ▒░ ░ ░▒  ░ ░ ▒ ░░ ░░   ░ ▒░    ░  
        ░            ░         ░   ▒     ░ ░ ▒  ░  ░  ░   ▒ ░   ░   ░ ░   ░      
                               ░  ░      ░ ░        ░   ░           ░          
"""
    print("\033[1m" + art + "\033[0m")
    print(" " * 38 + "owner - @Intelligenceleads")
    print("\n" + "=" * 70)
    print("Команды:")
    print("  meta <путь_к_файлу>   – извлечь метаданные (только существующие поля)")
    print("  whois <домен/IP>      – whois информация о домене или IP")
    print("  exit                  – выход")
    print("=" * 70 + "\n")

# ========== ОСНОВНОЙ ЦИКЛ ==========
def main():
    show_banner()
    while True:
        try:
            cmd = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nВыход.")
            break
        if not cmd:
            continue
        if cmd.lower() == "exit":
            print("Выход.")
            break
        parts = cmd.split(maxsplit=1)
        if len(parts) < 2:
            print("Недостаточно аргументов. Пример: meta C:\\photo.jpg  или  whois google.com")
            continue
        action, arg = parts[0].lower(), parts[1]
        if action == "meta":
            path = resolve_path(arg)
            if not path.exists():
                print(f"Файл не найден: {path}")
                continue
            data = get_metadata(path)
            def clean(d):
                if isinstance(d, dict):
                    return {k: clean(v) for k, v in d.items() if v not in ("", None, {})}
                return d
            cleaned = clean(data)
            if not cleaned or (len(cleaned) == 1 and "Сообщение" in cleaned):
                print(cleaned.get("Сообщение", "Метаданные отсутствуют."))
            else:
                print(json.dumps(cleaned, indent=2, ensure_ascii=False))
        elif action == "whois":
            result = whois_query(arg)
            print("\n" + result)
        else:
            print("Неизвестная команда. Доступны: meta, whois, exit")

if __name__ == "__main__":
    main()