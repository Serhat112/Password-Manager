import os
import sys
import sqlite3
import base64
from tkinter import *
from tkinter import messagebox
from tkinter import ttk
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

# ----------------------------
# Determine Database File Location
# ----------------------------
if sys.platform.startswith("win"):
    db_path = os.path.join(os.getenv("APPDATA"), "password_manager.db")
else:
    db_path = os.path.join(os.path.expanduser("~"), ".password_manager.db")

# ----------------------------
# Cryptography Helpers
# ----------------------------
def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# ----------------------------
# Database Handler Class
# ----------------------------
class DBHandler:
    def __init__(self, db_file):
        self.db_file = db_file
        self.conn = sqlite3.connect(self.db_file)
        self.cursor = self.conn.cursor()
        self.setup_db()

    def setup_db(self):
        # Create settings table (for main password and salt)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        # Create credentials table (for stored credentials)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account TEXT,
                enc_password TEXT
            )
        """)
        self.conn.commit()
        # Initialize settings if not present (default main password is "1111")
        self.cursor.execute("SELECT COUNT(*) FROM settings")
        if self.cursor.fetchone()[0] == 0:
            salt = os.urandom(16)
            key = derive_key("1111", salt)
            self.cursor.execute("INSERT INTO settings (key, value) VALUES (?, ?)",
                                ("main_password", key.decode()))
            self.cursor.execute("INSERT INTO settings (key, value) VALUES (?, ?)",
                                ("salt", base64.b64encode(salt).decode()))
            self.conn.commit()

    def get_setting(self, key):
        self.cursor.execute("SELECT value FROM settings WHERE key=?", (key,))
        row = self.cursor.fetchone()
        return row[0] if row else None

    def set_setting(self, key, value):
        self.cursor.execute("UPDATE settings SET value=? WHERE key=?", (value, key))
        self.conn.commit()

    def add_credential(self, account, enc_password):
        self.cursor.execute("INSERT INTO credentials (account, enc_password) VALUES (?, ?)",
                            (account, enc_password))
        self.conn.commit()

    def remove_credential(self, cred_id):
        self.cursor.execute("DELETE FROM credentials WHERE id=?", (cred_id,))
        self.conn.commit()

    def get_all_credentials(self):
        self.cursor.execute("SELECT id, account, enc_password FROM credentials")
        return self.cursor.fetchall()

    def update_credential(self, cred_id, enc_password):
        self.cursor.execute("UPDATE credentials SET enc_password=? WHERE id=?",
                            (enc_password, cred_id))
        self.conn.commit()

    def close(self):
        self.conn.close()

# ----------------------------
# Main Application Class
# ----------------------------
class PasswordManagerApp(Frame):
    def __init__(self, master, db_handler):
        Frame.__init__(self, master)
        self.master = master
        self.db = db_handler
        self.master.title("Şifre Yöneticisi")
        self.pack(padx=10, pady=10)
        self.fernet = None  # Will hold Fernet instance after login
        self.show_login_screen()

    def clear_widgets(self):
        for widget in self.winfo_children():
            widget.destroy()

    def show_login_screen(self):
        self.clear_widgets()
        self.login_frame = Frame(self)
        self.login_frame.pack(padx=10, pady=10)
        Label(self.login_frame, text="Ana Şifre:").pack(pady=5)
        self.login_entry = Entry(self.login_frame, show="*")
        self.login_entry.pack(pady=5)
        Button(self.login_frame, text="Giriş Yap", command=self.login).pack(pady=5)

    def login(self):
        entered = self.login_entry.get().strip()
        stored_key = self.db.get_setting("main_password")
        salt_b64 = self.db.get_setting("salt")
        if stored_key is None or salt_b64 is None:
            messagebox.showerror("Hata", "Ayarlar bulunamadı!")
            return
        salt = base64.b64decode(salt_b64.encode())
        entered_key = derive_key(entered, salt)
        if entered_key.decode() == stored_key:
            self.fernet = Fernet(entered_key)
            messagebox.showinfo("Başarılı", "Giriş başarılı!")
            self.show_main_menu()
        else:
            messagebox.showerror("Hata", "Yanlış ana şifre!")
            self.login_entry.delete(0, END)

    def show_main_menu(self):
        self.clear_widgets()
        self.menu_frame = Frame(self)
        self.menu_frame.pack(padx=10, pady=10)
        btn_frame = Frame(self.menu_frame)
        btn_frame.pack(pady=5)
        Button(btn_frame, text="Yeni Şifre Ekle", command=self.open_add_password_window).grid(row=0, column=0, padx=5)
        Button(btn_frame, text="Şifre Sil", command=self.remove_credential).grid(row=0, column=1, padx=5)
        Button(btn_frame, text="Ana Şifreyi Değiştir", command=self.open_change_main_password_window).grid(row=0, column=2, padx=5)
        Button(btn_frame, text="Çıkış", command=self.show_login_screen).grid(row=0, column=3, padx=5)
        Label(self.menu_frame, text="Kayıtlı Şifreler:").pack(anchor=W, pady=(10, 0))
        # Treeview for credentials
        self.tree = ttk.Treeview(self.menu_frame, columns=("ID", "Hesap", "Şifre"), show="headings")
        self.tree.heading("ID", text="ID")
        self.tree.heading("Hesap", text="Hesap")
        self.tree.heading("Şifre", text="Şifre")
        self.tree.column("ID", width=30)
        self.tree.column("Hesap", width=200)
        self.tree.column("Şifre", width=200)
        self.tree.pack(padx=5, pady=5, fill=BOTH, expand=True)
        self.refresh_credentials_tree()

    def refresh_credentials_tree(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        creds = self.db.get_all_credentials()
        for cred in creds:
            cred_id, account, enc_password = cred
            try:
                plain = self.fernet.decrypt(enc_password.encode()).decode()
            except Exception:
                plain = "Çözülemedi"
            self.tree.insert("", END, values=(cred_id, account, plain))

    def open_add_password_window(self):
        add_win = Toplevel(self.master)
        add_win.title("Yeni Şifre Ekle")
        add_win.geometry("300x150")
        Label(add_win, text="Hesap:").pack(padx=5, pady=5)
        account_entry = Entry(add_win)
        account_entry.pack(padx=5, pady=5)
        Label(add_win, text="Şifre:").pack(padx=5, pady=5)
        password_entry = Entry(add_win, show="*")
        password_entry.pack(padx=5, pady=5)

        def save_cred():
            account = account_entry.get().strip()
            password = password_entry.get().strip()
            if not account or not password:
                messagebox.showerror("Hata", "Hesap ve şifre boş olamaz!")
                return
            enc_password = self.fernet.encrypt(password.encode()).decode()
            self.db.add_credential(account, enc_password)
            messagebox.showinfo("Başarılı", "Şifre kaydedildi!")
            add_win.destroy()
            self.refresh_credentials_tree()

        Button(add_win, text="Kaydet", command=save_cred).pack(pady=5)

    def remove_credential(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("Hata", "Lütfen silinecek kaydı seçin!")
            return
        item = self.tree.item(selected[0])
        cred_id = item["values"][0]
        self.db.remove_credential(cred_id)
        messagebox.showinfo("Başarılı", "Kayıt silindi!")
        self.refresh_credentials_tree()

    def open_change_main_password_window(self):
        cp_win = Toplevel(self.master)
        cp_win.title("Ana Şifreyi Değiştir")
        cp_win.geometry("300x150")
        Label(cp_win, text="Mevcut Şifre:").pack(padx=5, pady=5)
        current_entry = Entry(cp_win, show="*")
        current_entry.pack(padx=5, pady=5)
        Label(cp_win, text="Yeni Şifre:").pack(padx=5, pady=5)
        new_entry = Entry(cp_win, show="*")
        new_entry.pack(padx=5, pady=5)

        def update_main_password():
            current = current_entry.get().strip()
            new = new_entry.get().strip()
            salt_b64 = self.db.get_setting("salt")
            if salt_b64 is None:
                messagebox.showerror("Hata", "Ayarlar hatalı!")
                return
            salt = base64.b64decode(salt_b64.encode())
            current_key = derive_key(current, salt)
            stored_key = self.db.get_setting("main_password")
            if current_key.decode() != stored_key:
                messagebox.showerror("Hata", "Mevcut şifre yanlış!")
                return
            if not new:
                messagebox.showerror("Hata", "Yeni şifre boş olamaz!")
                return
            # Derive new key and generate a new salt
            new_salt = os.urandom(16)
            new_key = derive_key(new, new_salt)
            # Update settings in the DB
            self.db.set_setting("main_password", new_key.decode())
            self.db.set_setting("salt", base64.b64encode(new_salt).decode())
            # Re-encrypt all credentials with the new key
            old_fernet = self.fernet
            new_fernet = Fernet(new_key)
            creds = self.db.get_all_credentials()
            for cred in creds:
                cred_id, account, enc_password = cred
                try:
                    plain = old_fernet.decrypt(enc_password.encode())
                except Exception:
                    continue
                new_enc = new_fernet.encrypt(plain).decode()
                self.db.update_credential(cred_id, new_enc)
            # Update our current fernet instance
            self.fernet = new_fernet
            messagebox.showinfo("Başarılı", "Ana şifre başarıyla değiştirildi!")
            cp_win.destroy()
            self.refresh_credentials_tree()

        Button(cp_win, text="Değiştir", command=update_main_password).pack(pady=5)

# ----------------------------
# Main Program
# ----------------------------
if __name__ == "__main__":
    root = Tk()
    db_handler = DBHandler(db_path)
    app = PasswordManagerApp(root, db_handler)
    root.mainloop()
