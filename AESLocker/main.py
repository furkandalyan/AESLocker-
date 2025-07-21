from tkinterdnd2 import DND_FILES, TkinterDnD
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.fernet import Fernet
import os
import shutil
import zipfile
import hashlib
import json
from datetime import datetime, timedelta
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import sys
import argparse
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import struct

file_path = None
key_path = None
folder_path = None
keyinfo_path = None

AESLOCK_HEADER = b'AESLOCK'
AESLOCK_HEADER_LEN = len(AESLOCK_HEADER)

EMBED_KEYINFO_HEADER = b'AESKINF'
EMBED_KEYINFO_HEADER_LEN = len(EMBED_KEYINFO_HEADER)


translations = {
    "tr": {
        "Select File/Folder": "Dosya/Klasör Seç:",
        "Select File/Folder Btn": "Dosya veya Klasör Seç",
        "Select Keyinfo": "Anahtar/Parola Dosyası (.keyinfo):",
        "Select Keyinfo Btn": "Anahtar/Parola Dosyası Seç",
        "Encrypt": "Şifrele",
        "Decrypt": "Çöz",
        "Encrypted": "✅ Dosya şifrelendi:",
        "Decrypted": "✅ Dosya çözüldü:",
        "Encrypted Files": "✅ {count} dosya şifrelendi.",
        "Keyinfo": "Anahtar/Parola dosyası:",
        "Password": "Parola",
        "Enter Password": "Lütfen bir parola belirleyin:",
        "Enter Password2": "Lütfen parolanızı girin:",
        "Enter Extensions": "Hangi uzantılar şifrelensin? (virgülle ayırın, örn: pdf,docx,jpg)",
        "Enter Expires": "Anahtar kaç dakika geçerli olsun? (Varsayılan: 1440)",
        "No Password": "Parola girilmedi.",
        "No Extensions": "Uzantı girilmedi.",
        "No File": "Lütfen bir dosya veya klasör seçin.",
        "No Keyinfo": "Dosya ve anahtar/parola dosyasını seçin.",
        "Wrong Password": "❌ Parola hatalı!",
        "Key Expired": "Anahtarın süresi dolmuş!",
        "Key Decrypt Error": "❌ Parola ile anahtar çözülemedi!",
        "Not AESF": "Bu dosya AESLocker formatında değil!",
        "Success": "Başarılı",
        "Error": "Hata",
        "Warning": "Uyarı",
        "Not Selected": "Henüz seçilmedi",
        "DragDrop": "📥 Dosya veya klasörü buraya sürükle-bırak",
        "AppTitle": "🔐 AESLocker - Dosya & Klasör Şifreleyici by Furkan Dalyan"
    },
    "en": {
        "Select File/Folder": "Select File/Folder:",
        "Select File/Folder Btn": "Select File or Folder",
        "Select Keyinfo": "Key/Password File (.keyinfo):",
        "Select Keyinfo Btn": "Select Key/Password File",
        "Encrypt": "Encrypt",
        "Decrypt": "Decrypt",
        "Encrypted": "✅ File encrypted:",
        "Decrypted": "✅ File decrypted:",
        "Encrypted Files": "✅ {count} files encrypted.",
        "Keyinfo": "Key/Password file:",
        "Password": "Password",
        "Enter Password": "Please set a password:",
        "Enter Password2": "Please enter your password:",
        "Enter Extensions": "Which extensions to encrypt? (comma separated, e.g. pdf,docx,jpg)",
        "Enter Expires": "How many minutes should the key be valid? (Default: 1440)",
        "No Password": "No password entered.",
        "No Extensions": "No extension entered.",
        "No File": "Please select a file or folder.",
        "No Keyinfo": "Select file and key/password file.",
        "Wrong Password": "❌ Wrong password!",
        "Key Expired": "Key expired!",
        "Key Decrypt Error": "❌ Could not decrypt key with password!",
        "Not AESF": "This file is not in AESLocker format!",
        "Success": "Success",
        "Error": "Error",
        "Warning": "Warning",
        "Not Selected": "Not selected yet",
        "DragDrop": "📥 Drag and drop file or folder here",
        "AppTitle": "🔐 AESLocker - File & Folder Encryptor by Furkan Dalyan"
    }
}

LANG = "tr"

def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("rsa_private.pem", "wb") as f:
        f.write(private_key)
    with open("rsa_public.pem", "wb") as f:
        f.write(public_key)
    return "rsa_private.pem", "rsa_public.pem"

def load_rsa_public_key(path):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())

def load_rsa_private_key(path):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def generate_keyinfo(password, expires=1440, cli_mode=False, rsa_pub_path=None, keyinfo_filename="mykey.keyinfo"):
    key = Fernet.generate_key()
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if not expires:
        expires = 1440
    salt = os.urandom(16)
    fernet_key = derive_key_from_password(password, salt)
    fernet_for_key = Fernet(fernet_key)
    encrypted_key = fernet_for_key.encrypt(key)
    rsa_encrypted_key = None
    if rsa_pub_path:
        rsa_pub = load_rsa_public_key(rsa_pub_path)
        cipher_rsa = PKCS1_OAEP.new(rsa_pub)
        rsa_encrypted_key = base64.urlsafe_b64encode(cipher_rsa.encrypt(key)).decode()
    keyinfo = {
        "key": base64.urlsafe_b64encode(encrypted_key).decode(),
        "password_hash": password_hash,
        "created": datetime.now().isoformat(timespec="minutes"),
        "expires_in_minutes": expires,
        "salt": base64.urlsafe_b64encode(salt).decode(),
        "rsa_encrypted_key": rsa_encrypted_key,
        "rsa_pub_path": rsa_pub_path
    }
    with open(keyinfo_filename, "w") as f:
        json.dump(keyinfo, f)
    return key, keyinfo_filename

def load_keyinfo(path):
    with open(path, "r") as f:
        keyinfo = json.load(f)
    return keyinfo


def read_file(path):
    with open(path, "rb") as f:
        return f.read()

def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)

# .aesf dosyasına keyinfo gömme

def write_aesf_file(path, encrypted_data, embed_keyinfo=None):
    with open(path, "wb") as f:
        f.write(AESLOCK_HEADER)
        if embed_keyinfo is not None:
            keyinfo_bytes = json.dumps(embed_keyinfo).encode()
            f.write(EMBED_KEYINFO_HEADER)
            f.write(struct.pack('>I', len(keyinfo_bytes)))
            f.write(keyinfo_bytes)
        f.write(encrypted_data)

def read_aesf_file(path):
    with open(path, "rb") as f:
        content = f.read()
    if not content.startswith(AESLOCK_HEADER):
        raise ValueError(translations[LANG]["Not AESF"])
    idx = AESLOCK_HEADER_LEN
    embed_keyinfo = None
    if content[idx:idx+EMBED_KEYINFO_HEADER_LEN] == EMBED_KEYINFO_HEADER:
        idx += EMBED_KEYINFO_HEADER_LEN
        keyinfo_len = struct.unpack('>I', content[idx:idx+4])[0]
        idx += 4
        keyinfo_bytes = content[idx:idx+keyinfo_len]
        embed_keyinfo = json.loads(keyinfo_bytes.decode())
        idx += keyinfo_len
    encrypted_data = content[idx:]
    return encrypted_data, embed_keyinfo


def browse_file():
    global file_path, folder_path
    path = filedialog.askopenfilename()
    if not path:
        path = filedialog.askdirectory()
        if path:
            folder_path = path
            file_path = None
            label_file.config(text=f"Klasör: {os.path.basename(path)}")
        else:
            file_path = None
            folder_path = None
            label_file.config(text="Henüz seçilmedi")
    else:
        file_path = path
        folder_path = None
        label_file.config(text=os.path.basename(path))

def browse_keyinfo_file():
    global keyinfo_path
    path = filedialog.askopenfilename(filetypes=[("KeyInfo Files", "*.keyinfo")])
    keyinfo_path = path
    label_key.config(text=os.path.basename(path))

def encrypt():
    if folder_path:
        encrypt_folder()
    elif file_path:
        encrypt_file()
    else:
        messagebox.showwarning("Uyarı", "Lütfen bir dosya veya klasör seçin.")

def decrypt():
    if folder_path:
        decrypt_folder()
    elif file_path:
        decrypt_file()
    else:
        messagebox.showwarning("Uyarı", "Lütfen bir dosya veya klasör seçin.")

LOG_FILE = "aeslocker.log"

def log_action(action, filename, result):
    with open(LOG_FILE, "a", encoding="utf-8") as logf:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        logf.write(f"[{timestamp}] {action}: {filename} {result}\n")


# --- Dosya şifrele ---
def encrypt_file():
    if not file_path:
        messagebox.showwarning(translations[LANG]["Warning"], translations[LANG]["No File"])
        return
    password = simpledialog.askstring(translations[LANG]["Password"], translations[LANG]["Enter Password"], show='*')
    if not password:
        messagebox.showwarning(translations[LANG]["Warning"], translations[LANG]["No Password"])
        return
    keyinfo_filename = simpledialog.askstring("Keyinfo", ".keyinfo dosya adı (örn: mykey.keyinfo):", initialvalue="mykey.keyinfo")
    if not keyinfo_filename:
        keyinfo_filename = "mykey.keyinfo"
    embed = messagebox.askyesno("Keyinfo Göm", ".keyinfo dosyasını .aesf dosyasına gömmek ister misiniz?")
    try:
        key, keyinfo_filename = generate_keyinfo(password, keyinfo_filename=keyinfo_filename)
        fernet = Fernet(key)
        data = read_file(file_path)
        encrypted = fernet.encrypt(data)
        aesf_path = file_path + ".aesf"
        embed_keyinfo = None
        if embed:
            with open(keyinfo_filename, "r") as f:
                embed_keyinfo = json.load(f)
        write_aesf_file(aesf_path, encrypted, embed_keyinfo=embed_keyinfo)
        messagebox.showinfo(translations[LANG]["Success"], f"{translations[LANG]["Encrypted"]}\n{aesf_path}\n{translations[LANG]["Keyinfo"]} {keyinfo_filename}" + ("\n(keyinfo gömülü)" if embed else ""))
        log_action("Encrypted file", file_path, "(Success)")
    except Exception as e:
        messagebox.showerror(translations[LANG]["Error"], str(e))
        log_action("Encrypted file", file_path, f"(Failed: {e})")


# --- Dosya çöz ---
def decrypt_file():
    global keyinfo_path
    if not file_path:
        messagebox.showwarning(translations[LANG]["Warning"], translations[LANG]["No File"])
        return
    password = simpledialog.askstring(translations[LANG]["Password"], translations[LANG]["Enter Password2"], show='*')
    if not password:
        messagebox.showwarning(translations[LANG]["Warning"], translations[LANG]["No Password"])
        return
    try:
        encrypted, embed_keyinfo = read_aesf_file(file_path)
        keyinfo = None
        if keyinfo_path:
            keyinfo = load_keyinfo(keyinfo_path)
        elif embed_keyinfo:
            keyinfo = embed_keyinfo
        else:
            messagebox.showwarning(translations[LANG]["Warning"], translations[LANG]["No Keyinfo"])
            return
        created = datetime.fromisoformat(keyinfo["created"])
        expires = keyinfo["expires_in_minutes"]
        if datetime.now() > created + timedelta(minutes=expires):
            messagebox.showerror(translations[LANG]["Error"], translations[LANG]["Key Expired"])
            log_action("Decrypted file", file_path, "(Failed: Key expired)")
            return
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if password_hash != keyinfo["password_hash"]:
            messagebox.showerror(translations[LANG]["Error"], translations[LANG]["Wrong Password"])
            log_action("Decrypted file", file_path, "(Failed: Wrong password)")
            return
        key = None
        if keyinfo.get("rsa_encrypted_key"):
            priv_path = filedialog.askopenfilename(title="RSA Private Key", filetypes=[("PEM Files", "*.pem")])
            if not priv_path:
                messagebox.showwarning(translations[LANG]["Warning"], "RSA private key seçilmedi.")
                return
            rsa_priv = load_rsa_private_key(priv_path)
            cipher_rsa = PKCS1_OAEP.new(rsa_priv)
            try:
                key = cipher_rsa.decrypt(base64.urlsafe_b64decode(keyinfo["rsa_encrypted_key"]))
            except Exception:
                messagebox.showerror(translations[LANG]["Error"], "RSA anahtar çözümü başarısız!")
                log_action("Decrypted file", file_path, "(Failed: RSA key decrypt error)")
                return
        else:
            salt = base64.urlsafe_b64decode(keyinfo["salt"])
            fernet_key = derive_key_from_password(password, salt)
            fernet_for_key = Fernet(fernet_key)
            encrypted_key = base64.urlsafe_b64decode(keyinfo["key"])
            try:
                key = fernet_for_key.decrypt(encrypted_key)
            except Exception:
                messagebox.showerror(translations[LANG]["Error"], translations[LANG]["Key Decrypt Error"])
                log_action("Decrypted file", file_path, "(Failed: Key decrypt error)")
                return
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted)
        dec_path = file_path.replace(".aesf", ".decrypted")
        write_file(dec_path, decrypted)
        messagebox.showinfo(translations[LANG]["Success"], f"{translations[LANG]["Decrypted"]}\n{dec_path}")
        log_action("Decrypted file", file_path, "(Success)")
    except Exception as e:
        messagebox.showerror(translations[LANG]["Error"], "❌ Parola veya dosya hatalı!\n" + str(e))
        log_action("Decrypted file", file_path, f"(Failed: {e})")


def encrypt_folder():
    
    ext_str = simpledialog.askstring("Uzantılar", "Hangi uzantılar şifrelensin? (virgülle ayırın, örn: pdf,docx,jpg)")
    if not ext_str:
        messagebox.showwarning(translations[LANG]["Warning"], translations[LANG]["No Extensions"])
        return
    extensions = [e.strip().lower() for e in ext_str.split(",") if e.strip()]
    password = simpledialog.askstring(translations[LANG]["Password"], translations[LANG]["Enter Password"], show='*')
    if not password:
        messagebox.showwarning(translations[LANG]["Warning"], translations[LANG]["No Password"])
        return
    keyinfo_filename = simpledialog.askstring("Keyinfo", ".keyinfo dosya adı (örn: mykey.keyinfo):", initialvalue="mykey.keyinfo")
    if not keyinfo_filename:
        keyinfo_filename = "mykey.keyinfo"
    try:
        key, keyinfo_filename = generate_keyinfo(password, keyinfo_filename=keyinfo_filename)
        fernet = Fernet(key)
        count = 0
        for rootdir, _, files in os.walk(folder_path):
            for fname in files:
                if any(fname.lower().endswith(f".{ext}") for ext in extensions):
                    fpath = os.path.join(rootdir, fname)
                    try:
                        data = read_file(fpath)
                        encrypted = fernet.encrypt(data)
                        aesf_path = fpath + ".aesf"
                        write_aesf_file(aesf_path, encrypted)
                        log_action("Encrypted file", fpath, "(Success)")
                        count += 1
                    except Exception as e:
                        log_action("Encrypted file", fpath, f"(Failed: {e})")
        messagebox.showinfo(translations[LANG]["Success"], f"{translations[LANG]["Encrypted Files"].format(count=count)}\n{translations[LANG]["Keyinfo"]} {keyinfo_filename}")
    except Exception as e:
        messagebox.showerror(translations[LANG]["Error"], str(e))
        log_action("Encrypted folder", folder_path, f"(Failed: {e})")

def decrypt_folder():
    global keyinfo_path
    if not file_path:
        messagebox.showwarning(translations[LANG]["Warning"], translations[LANG]["No File"])
        return
    password = simpledialog.askstring(translations[LANG]["Password"], translations[LANG]["Enter Password2"], show='*')
    if not password:
        messagebox.showwarning(translations[LANG]["Warning"], translations[LANG]["No Password"])
        return
    try:
        encrypted, embed_keyinfo = read_aesf_file(file_path)
        keyinfo = None
        if keyinfo_path:
            keyinfo = load_keyinfo(keyinfo_path)
        elif embed_keyinfo:
            keyinfo = embed_keyinfo
        else:
            messagebox.showwarning(translations[LANG]["Warning"], translations[LANG]["No Keyinfo"])
            return
        created = datetime.fromisoformat(keyinfo["created"])
        expires = keyinfo["expires_in_minutes"]
        if datetime.now() > created + timedelta(minutes=expires):
            messagebox.showerror(translations[LANG]["Error"], translations[LANG]["Key Expired"])
            log_action("Decrypted folder", file_path, "(Failed: Key expired)")
            return
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if password_hash != keyinfo["password_hash"]:
            messagebox.showerror(translations[LANG]["Error"], translations[LANG]["Wrong Password"])
            log_action("Decrypted folder", file_path, "(Failed: Wrong password)")
            return
        salt = base64.urlsafe_b64decode(keyinfo["salt"])
        fernet_key = derive_key_from_password(password, salt)
        fernet_for_key = Fernet(fernet_key)
        encrypted_key = base64.urlsafe_b64decode(keyinfo["key"])
        try:
            key = fernet_for_key.decrypt(encrypted_key)
        except Exception:
            messagebox.showerror(translations[LANG]["Error"], translations[LANG]["Key Decrypt Error"])
            log_action("Decrypted folder", file_path, "(Failed: Key decrypt error)")
            return
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted)
        zip_out = file_path.replace(".aesf", ".zip")
        write_file(zip_out, decrypted)
        # Orijinal klasör adını bul ve oraya çıkar
        with zipfile.ZipFile(zip_out, 'r') as zip_ref:
            namelist = zip_ref.namelist()
            # Ana klasör bul
            top_dirs = set([n.split('/')[0] for n in namelist if n and '/' in n])
            if len(top_dirs) == 1:
                extract_dir = list(top_dirs)[0]
            else:
                extract_dir = zip_out.replace('.zip', '')
            os.makedirs(extract_dir, exist_ok=True)
            zip_ref.extractall(extract_dir)
        os.remove(zip_out)
        messagebox.showinfo(translations[LANG]["Success"], f"✅ Klasör çözüldü:\n{extract_dir}")
        log_action("Decrypted folder", file_path, "(Success)")
    except Exception as e:
        messagebox.showerror(translations[LANG]["Error"], str(e))
        log_action("Decrypted folder", file_path, f"(Failed: {e})")


def on_drop(event):
    global file_path, folder_path
    dropped = event.data.strip("{}")
    if os.path.isdir(dropped):
        folder_path = dropped
        file_path = None
        label_file.config(text=f"Klasör: {os.path.basename(folder_path)}")
    elif os.path.isfile(dropped):
        file_path = dropped
        folder_path = None
        label_file.config(text=os.path.basename(file_path))

def on_generate_rsa():
    priv_path, pub_path = generate_rsa_keys()
    messagebox.showinfo("RSA", f"RSA anahtar çifti oluşturuldu!\nPublic: {pub_path}\nPrivate: {priv_path}")


root = TkinterDnD.Tk()
root.title(translations[LANG]["AppTitle"])
root.iconbitmap("lock.ico")
root.geometry("900x700")
root.configure(bg="#e9ecef")

HEADER_FONT = ("Segoe UI", 20, "bold")
LABEL_FONT = ("Segoe UI", 16)
BUTTON_FONT = ("Segoe UI", 16, "bold")
BUTTON_WIDTH = 36
BUTTON_PADY = 14
BUTTON_PADX = 10

frame_drop = tk.Label(
    root,
    text=translations[LANG]["DragDrop"],
    bg="#e9ecef",
    relief="groove",
    height=3,
    font=HEADER_FONT
)
frame_drop.pack(pady=20, fill="x", padx=40)
frame_drop.drop_target_register(DND_FILES)
frame_drop.dnd_bind("<<Drop>>", on_drop)

tk.Label(root, text=translations[LANG]["Select File/Folder"], bg="#e9ecef", font=HEADER_FONT).pack(pady=(20, 8))
label_file = tk.Label(root, text=translations[LANG]["Not Selected"], fg="gray", bg="#e9ecef", font=LABEL_FONT)
label_file.pack(pady=(0, 8))
tk.Button(
    root, text=translations[LANG]["Select File/Folder Btn"], command=browse_file, font=BUTTON_FONT, relief="ridge", bd=2, bg="#f0f0f0",
    width=BUTTON_WIDTH, padx=BUTTON_PADX, pady=BUTTON_PADY
).pack(pady=(0, 18))

tk.Label(root, text=translations[LANG]["Select Keyinfo"], bg="#e9ecef", font=HEADER_FONT).pack(pady=(10, 8))
label_key = tk.Label(root, text=translations[LANG]["Not Selected"], fg="gray", bg="#e9ecef", font=LABEL_FONT)
label_key.pack(pady=(0, 8))
tk.Button(
    root, text=translations[LANG]["Select Keyinfo Btn"], command=browse_keyinfo_file, font=BUTTON_FONT, relief="ridge", bd=2, bg="#f0f0f0",
    width=BUTTON_WIDTH, padx=BUTTON_PADX, pady=BUTTON_PADY
).pack(pady=(0, 18))

tk.Button(
    root, text="RSA Anahtar Üret", command=on_generate_rsa, font=BUTTON_FONT, relief="ridge", bd=2, bg="#f0f0f0",
    width=BUTTON_WIDTH, padx=BUTTON_PADX, pady=BUTTON_PADY
).pack(pady=(0, 18))

tk.Button(
    root, text=translations[LANG]["Encrypt"], command=encrypt, bg="#4CAF50", fg="white", width=BUTTON_WIDTH, font=BUTTON_FONT, relief="ridge", bd=2,
    padx=BUTTON_PADX, pady=BUTTON_PADY
).pack(pady=(0, 10))
tk.Button(
    root, text=translations[LANG]["Decrypt"], command=decrypt, bg="#2196F3", fg="white", width=BUTTON_WIDTH, font=BUTTON_FONT, relief="ridge", bd=2,
    padx=BUTTON_PADX, pady=BUTTON_PADY
).pack(pady=(0, 30))

root.mainloop()