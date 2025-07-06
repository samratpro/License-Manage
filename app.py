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
    now = datetime.datetime.now().date()
    then = datetime.datetime.strptime(last_reset, "%Y-%m-%d").date()
    if mode == "daily":
        return now > then
    elif mode == "weekly":
        return (now - then).days >= 7
    elif mode == "monthly":
        return now.month != then.month or now.year != then.year
    elif mode == "yearly":
        return now.year != then.year
    return False

def reset_credit(data):
    data["credit"] = data.get("max_credit", data["credit"])
    data["last_reset"] = datetime.datetime.now().strftime("%Y-%m-%d")
    sync_to_all_locations(data)

def create_or_update_license():
    license_key = input("🔑 Enter license key: ").strip()
    credit = int(input("💳 Enter credit amount: ").strip())
    expiry = input("📆 Enter expiry date (YYYY-MM-DD): ").strip()
    reset_mode = input("🔁 Credit reset mode (daily/weekly/monthly/yearly): ").strip().lower()

    current_ip, current_location = get_ip_location()
    data = {
        "license": license_key,
        "credit": credit,
        "max_credit": credit,
        "expiry": expiry,
        "reset_mode": reset_mode,
        "last_reset": datetime.datetime.now().strftime("%Y-%m-%d"),
        "ip": current_ip,
        "location": current_location
    }
    sync_to_all_locations(data)
    print("✅ License saved.")

def update_expiry():
    data = load_license()
    if not data:
        print("⚠️ No valid license found.")
        return
    new_expiry = input("📆 Enter new expiry date (YYYY-MM-DD): ").strip()
    data["expiry"] = new_expiry
    sync_to_all_locations(data)
    print("✅ Expiry date updated.")

def check_expiry():
    data = load_license()
    if not data:
        print("⚠️ No valid license found.")
        return
    expiry = datetime.datetime.strptime(data["expiry"], "%Y-%m-%d").date()
    now = datetime.datetime.now().date()
    if now > expiry:
        print("❌ License expired.")
    else:
        print(f"✅ License valid until {data['expiry']}")

def use_credit():
    data = load_license()
    if not data:
        print("⚠️ No valid license found.")
        return
    if should_reset(data["last_reset"], data["reset_mode"]):
        reset_credit(data)
    if data["credit"] > 0:
        data["credit"] -= 1
        sync_to_all_locations(data)
        print(f"✅ Credit used. Remaining: {data['credit']}")
    else:
        print("❌ No credits left.")

def view_license():
    data = load_license()
    if not data:
        print("⚠️ No valid license found.")
        return
    if should_reset(data["last_reset"], data["reset_mode"]):
        reset_credit(data)
    print("🔐 License Info:")
    for k, v in data.items():
        print(f"  {k.capitalize():<12}: {v}")

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
