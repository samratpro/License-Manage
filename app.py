import os
import json
import base64
import hashlib
import psutil
import datetime
import requests
from cryptography.fernet import Fernet, InvalidToken

APP_NAME = "MS_Windows_AppData"
SALT = b"UltraSecretSalt_ChangeMe"

LOCATIONS = [
    os.path.join(os.getenv("APPDATA"), APP_NAME, "license1.dat"),
    os.path.join(os.getenv("LOCALAPPDATA"), APP_NAME, "system", "cache.lic"),
    os.path.join(os.getenv("PROGRAMDATA"), "System32Hidden", "data", "core.lic"),
    os.path.join(os.getenv("TEMP"), ".hidden_secure", "session.sec"),
    os.path.join("C:\\ProgramData\\.sys_" + APP_NAME, "hidden.lic"),
]

def get_device_fingerprint():
    for iface in psutil.net_if_addrs().values():
        for snic in iface:
            if snic.family.name == 'AF_LINK' and snic.address != '00:00:00:00:00:00':
                return snic.address
    return "UNKNOWN_DEVICE"

def generate_key():
    fingerprint = get_device_fingerprint()
    hashed = hashlib.pbkdf2_hmac("sha256", SALT, fingerprint.encode(), 100000)
    return base64.urlsafe_b64encode(hashed[:32])

def encrypt_data(data: dict) -> bytes:
    key = generate_key()
    f = Fernet(key)
    return f.encrypt(json.dumps(data).encode())

def decrypt_data(encrypted: bytes) -> dict:
    key = generate_key()
    f = Fernet(key)
    return json.loads(f.decrypt(encrypted).decode())

def write_to_locations(encrypted_data):
    for path in LOCATIONS:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(encrypted_data)
        except Exception as e:
            print(f"⚠️ Failed to write to {path}: {e}")

def read_from_locations():
    # First try to find a valid license
    for path in LOCATIONS:
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    encrypted = f.read()
                    # Test decryption to verify it's valid
                    decrypt_data(encrypted)
                    return encrypted, path
            except:
                continue
    
    # If none found, return None
    return None, None

def repair_license_files(source_data):
    """Recreate all license files from source data"""
    encrypted = encrypt_data(source_data)
    write_to_locations(encrypted)
    print("🛠️ License files repaired")

def sync_to_all_locations(data: dict):
    encrypted = encrypt_data(data)
    write_to_locations(encrypted)

def remove_all_files():
    for path in LOCATIONS:
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception as e:
            print(f"⚠️ Failed to remove {path}: {e}")

def safe_parse_datetime(date_str):
    """Parse datetime string with fallback handling"""
    try:
        return datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        try:
            return datetime.datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError:
            # If parsing fails completely, return current datetime
            return datetime.datetime.now()

def get_ip_location():
    try:
        ip = requests.get("https://api.ipify.org?format=json", timeout=5).json().get("ip")
        if ip:
            info = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5).json()
            location = info.get("city", "") + ", " + info.get("country", "")
        else:
            ip = None
            location = None
        return ip, location
    except Exception:
        return None, None

def load_license():
    encrypted, found_path = read_from_locations()
    if encrypted:
        try:
            data = decrypt_data(encrypted)
            
            # Verify all locations exist and are valid
            for path in LOCATIONS:
                if not os.path.exists(path):
                    repair_license_files(data)
                    break
                else:
                    try:
                        with open(path, "rb") as f:
                            test_data = f.read()
                            decrypt_data(test_data)
                    except:
                        repair_license_files(data)
                        break
            
            # Update IP/location if changed
            current_ip, current_location = get_ip_location()
            if data.get("ip") != current_ip or data.get("location") != current_location:
                data["ip"] = current_ip
                data["location"] = current_location
                sync_to_all_locations(data)
                
            return data
        except InvalidToken:
            print("❌ License is invalid or tampered!")
    return None

def should_reset(last_reset, mode):
    if mode == "Unlimited":
        return False
    now = datetime.datetime.now()
    then = safe_parse_datetime(last_reset)

    if mode == "daily":
        return now.date() > then.date()
    elif mode == "weekly":
        return (now - then).days >= 7
    elif mode == "monthly":
        return now.month != then.month or now.year != then.year
    elif mode == "yearly":
        return now.year != then.year
    return False

def reset_credit(data):
    data["credit"] = data.get("max_credit", data["credit"])
    data["last_reset"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sync_to_all_locations(data)

def create_or_update_license():
    fingerprint = get_device_fingerprint()
    license_key = input("🔑 Enter license key: ").strip()
    credit = int(input("💳 Enter credit amount: ").strip())
    license_type = input("🔑 Enter license Type (e.g Monthly/Yearly/Lifetime): ").strip()
    expiry_input = input("📆 Enter license duration in days (or 'Never'): ").strip()
    if expiry_input.lower() == "never":
        expiry = "Never"
    else:
        try:
            days = int(expiry_input)
            expiry_date = datetime.datetime.now() + datetime.timedelta(days=days)
            expiry = expiry_date.strftime("%Y-%m-%d")
        except ValueError:
            print("❌ Invalid input. Please enter a number or 'Never'.")
            return
    reset_mode = input("🔁 Credit reset mode (Daily/Weekly/Monthly/Yearly/Unlimited): ").strip()
    if reset_mode not in ["Daily", "Weekly", "Monthly", "Yearly", "Unlimited"]:
        print("❌ Invalid reset mode.")
        return

    current_ip, current_location = get_ip_location()
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Check if license already exists to determine if it's activation or update
    existing_data = load_license()
    is_update = existing_data is not None
    
    data = {
        "mac": fingerprint,
        "license": license_key,
        "credit": credit,
        "max_credit": credit,
        "license_type": license_type,
        "expiry": expiry,
        "reset_mode": reset_mode,
        "last_reset": current_time,
        "activate_time": current_time,  # Always update activation time
        "ip": current_ip,
        "location": current_location
    }
    
    # If updating existing license, preserve original activate_time if user wants
    if is_update and existing_data.get("activate_time"):
        preserve = input("🔄 Keep original activation time? (y/n): ").strip().lower()
        if preserve == 'y':
            data["activate_time"] = existing_data["activate_time"]
            print(f"📅 Preserving original activation time: {existing_data['activate_time']}")
        else:
            print(f"📅 Updated activation time: {current_time}")
    else:
        print(f"📅 License activated at: {current_time}")
    
    sync_to_all_locations(data)
    action = "updated" if is_update else "created and activated"
    print(f"✅ License {action}.")

def update_expiry():
    data = load_license()
    if not data:
        print("⚠️ No valid license found.")
        return
    new_expiry = input("📆 Enter new expiry date (YYYY-MM-DD): ").strip()
    data["expiry"] = new_expiry
    
    # Update activate_time when expiry is updated
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    update_activation = input("🔄 Update activation time? (y/n): ").strip().lower()
    if update_activation == 'y':
        data["activate_time"] = current_time
        print(f"📅 Activation time updated: {current_time}")
    
    sync_to_all_locations(data)
    print("✅ Expiry date updated.")

def is_expired(data):
    try:
        if data["expiry"] == "Never":
            return False
        expiry = datetime.datetime.strptime(data["expiry"], "%Y-%m-%d").date()
        return datetime.datetime.now().date() > expiry
    except Exception:
        return False

def check_expiry():
    data = load_license()
    if not data:
        print("⚠️ No valid license found.")
        return
    expiry = data.get("expiry")
    if expiry == "Never":
        print("♾️ License is lifetime (never expires).")
    else:
        try:
            expiry_date = datetime.datetime.strptime(expiry, "%Y-%m-%d").date()
            now = datetime.datetime.now().date()
            if now > expiry_date:
                print("❌ License expired.")
            else:
                print(f"✅ License valid until {expiry}")
        except ValueError:
            print("❌ Invalid expiry date format.")

def use_credit():
    data = load_license()
    if not data:
        print("⚠️ No valid license found.")
        return
    if is_expired(data):
        print("❌ License expired. Cannot use credits.")
        return
    if should_reset(data["last_reset"], data["reset_mode"]):
        reset_credit(data)
        data = load_license()  # Reload updated data
    if data["credit"] > 0:
        data["credit"] -= 1
        sync_to_all_locations(data)
        print(f"✅ Credit used. Remaining: {data['credit']}")
    else:
        print("❌ No credits left.")

def get_next_reset_date(last_reset, mode):
    """Calculate next reset date based on mode"""
    then = safe_parse_datetime(last_reset)
    
    if mode == "daily":
        return then + datetime.timedelta(days=1)
    elif mode == "weekly":
        return then + datetime.timedelta(days=7)
    elif mode == "monthly":
        if then.month == 12:
            return then.replace(year=then.year + 1, month=1)
        else:
            return then.replace(month=then.month + 1)
    elif mode == "yearly":
        return then.replace(year=then.year + 1)
    return None


def view_license():
    data = load_license()
    if not data:
        print("⚠️ No valid license found.")
        return

    if is_expired(data):
        print("❌ License expired. Cannot view details.")
        return

    # Check if reset is needed
    if should_reset(data["last_reset"], data["reset_mode"]):
        reset_credit(data)
        data = load_license()  # Reload updated data

    print("🔐 License Info:")

    # Define display order and labels
    display_fields = [
        ("license", "License"),
        ("mac", "MAC Address"),
        ("credit", "Credit"),
        ("max_credit", "Max Credit"),
        ("license_type", "License Type"),
        ("expiry", "Expiry"),
        ("reset_mode", "Reset Mode"),
        ("activate_time", "Activated"),
        ("last_reset", "Last Reset"),
        ("ip", "IP"),
        ("location", "Location")
    ]

    for key, label in display_fields:
        if key in data and data[key] is not None:
            value = data[key]
            if key in ["last_reset", "activate_time"]:
                try:
                    dt = safe_parse_datetime(str(value))
                    value = dt.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    pass
            print(f"  {label:<12}: {value}")

    next_reset = get_next_reset_date(data["last_reset"], data["reset_mode"])
    if next_reset:
        formatted = next_reset.strftime('%Y-%m-%d %H:%M:%S')
        print(f"  {'Next Reset':<12}: {formatted}")
        data["next_reset"] = formatted  # ✅ Add next reset to returned dict

    if data.get("activate_time"):
        try:
            activate_dt = safe_parse_datetime(data["activate_time"])
            age = datetime.datetime.now() - activate_dt
            days = age.days
            hours = age.seconds // 3600
            print(f"  {'License Age':<12}: {days} days, {hours} hours")
        except:
            pass

    return data

def show_paths():
    print("\n📂 License File Paths:")
    for path in LOCATIONS:
        exists = "✅" if os.path.exists(path) else "❌"
        print(f"  {exists} {path}")

def main():
    while True:
        print("\n=== Secure License Console ===")
        print("1. View License Info")
        print("2. Use 1 Credit")
        print("3. Check Expiry")
        print("4. Update Expiry")
        print("5. Set License (Full)")
        print("6. Remove License")
        print("7. Show License Paths")
        print("8. Exit")

        choice = input("Choose (1–8): ").strip()

        if choice == "1":
            view_license()
        elif choice == "2":
            use_credit()
        elif choice == "3":
            check_expiry()
        elif choice == "4":
            update_expiry()
        elif choice == "5":
            create_or_update_license()
        elif choice == "6":
            remove_all_files()
            print("🧹 License removed.")
        elif choice == "7":
            show_paths()
        elif choice == "8":
            print("👋 Exiting.")
            break
        else:
            print("❌ Invalid choice.")

if __name__ == "__main__":
    main()
