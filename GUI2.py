import tkinter as tk
from tkinter import messagebox
import bcrypt
import secrets
import string
import os
import json
import base64

DATA_FILE = 'users.json'
PASSWORDS_FILE = 'generated_passwords.json'


# --- bcrypt hashing ---
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return base64.b64encode(hashed).decode('utf-8')


def verify_password(stored_hash, password):
    try:
        hashed_bytes = base64.b64decode(stored_hash.encode('utf-8'))
        return bcrypt.checkpw(password.encode('utf-8'), hashed_bytes)
    except Exception as e:
        print(f"Error in verifying password: {e}")
        return False

# --- Encryption Helpers ---
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def encrypt_password(password: str, fernet: Fernet) -> str:
    return fernet.encrypt(password.encode()).decode()

def decrypt_password(token: str, fernet: Fernet) -> str:
    return fernet.decrypt(token.encode()).decode()

# --- File I/O ---
def load_users():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}


def load_generated_passwords():
    if os.path.exists(PASSWORDS_FILE):
        with open(PASSWORDS_FILE, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}


def save_user(email, password, username=None, is_hashed=False):
    users = load_users()

    if not is_hashed:
        password = hash_password(password)

    if email not in users:
        salt = base64.b64encode(os.urandom(16)).decode()
    else:
        salt = users[email].get("salt")

    users[email] = {
        "password": password,
        "username": username if username else "",
        "salt": salt
    }

    with open(DATA_FILE, 'w') as f:
        json.dump(users, f, indent=4)



def save_generated_password(label, username, password, email, fernet):
    passwords = load_generated_passwords()

    if email not in passwords:
        passwords[email] = {}

    encrypted_pw = encrypt_password(password, fernet)

    passwords[email][label] = {
        "username": username,
        "password_enc": encrypted_pw,   # encrypted only
        "email": email
    }

    with open(PASSWORDS_FILE, 'w') as f:
        json.dump(passwords, f, indent=4)





# --- Authentication popup ---
class AuthPage(tk.Toplevel):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.title("Login or Register")
        self.geometry("400x250")
        self.transient(parent)
        self.grab_set()

        tk.Label(self, text="Email:").pack()
        self.email_entry = tk.Entry(self)
        self.email_entry.pack()

        tk.Label(self, text="Password:").pack()
        self.password_entry = tk.Entry(self, show="*")
        self.password_entry.pack()

        tk.Button(self, text="Login", command=self.login).pack(pady=5)
        tk.Button(self, text="Register", command=self.register).pack()

    def login(self):
        email = self.email_entry.get().strip()
        password = self.password_entry.get().strip()
        users = load_users()

        if email in users:
            stored_hash = users[email].get("password", "")
            if stored_hash and verify_password(stored_hash, password):

                salt = base64.b64decode(users[email]["salt"].encode())
                key = derive_key(password, salt)
                self.app.fernet = Fernet(key)


                self.app.email = email
                self.app.authenticated = True
                self.destroy()
            else:
                messagebox.showerror("Error", "Incorrect password.")
        else:
            messagebox.showerror("Error", "User not found.")

    def register(self):
        email = self.email_entry.get()
        password = self.password_entry.get()
        users = load_users()
        if email in users:
            messagebox.showerror("Error", "Account already exists.")
        else:
            save_user(email, password)
            users = load_users()

            salt = base64.b64decode(users[email]["salt"].encode())
            key = derive_key(password, salt)
            self.app.fernet = Fernet(key)

            messagebox.showinfo("Success", "Account created.")
            self.app.email = email
            self.app.authenticated = True
            self.destroy()


class PasswordGeneratorPage(tk.Frame):
    def __init__(self, parent, controller, page_names):
        super().__init__(parent)
        self.controller = controller

        tk.Label(self, text="Website/App Name:").pack()
        self.site_entry = tk.Entry(self)
        self.site_entry.pack()

        tk.Label(self, text="Username:").pack()
        self.username_entry = tk.Entry(self)
        self.username_entry.pack()

        tk.Label(self, text="Password Length:").pack()
        self.length_entry = tk.Entry(self)
        self.length_entry.pack()

        self.use_letters = tk.BooleanVar()
        self.use_numbers = tk.BooleanVar()
        self.use_specials = tk.BooleanVar()

        tk.Checkbutton(self, text="Include Letters", variable=self.use_letters).pack()
        tk.Checkbutton(self, text="Include Numbers", variable=self.use_numbers).pack()
        tk.Checkbutton(self, text="Include Special Characters", variable=self.use_specials).pack()

        self.result_label = tk.Label(self, text="")
        self.result_label.pack()

        tk.Button(self, text="Generate Password", command=self.generate_password).pack()
        tk.Button(self, text="Save Password", command=self.save_password).pack(pady=5)

        self.create_navbar(page_names)

    def save_password(self):
        label = self.site_entry.get().strip()
        username = self.username_entry.get().strip()
        password_text = self.result_label.cget("text").replace("Generated: ", "").strip()

        if not (label and username and password_text):
            messagebox.showwarning("Missing Info", "Please generate a password and fill in Website/App Name and Username.")
            return

        save_generated_password(label, username, password_text, self.controller.email, self.controller.fernet)
        messagebox.showinfo("Saved", f"Password saved for {label}")


    def generate_password(self):
        try:
            length = int(self.length_entry.get())
            if length < 8 or length > 20:
                raise ValueError("Length must be between 8 and 20")
            chars = ""
            if self.use_letters.get():
                chars += string.ascii_letters
            if self.use_numbers.get():
                chars += string.digits
            if self.use_specials.get():
                chars += string.punctuation
            if not chars:
                raise ValueError("Select at least one character type")
            password = ''.join(secrets.choice(chars) for _ in range(length))
            self.result_label.config(text=f"Generated: {password}")

        except Exception as e:
            self.result_label.config(text=f"Error: {e}")

    def create_navbar(self, page_names):
        nav_frame = tk.Frame(self)
        nav_frame.pack(side=tk.BOTTOM, pady=10)
        for name in page_names:
            tk.Button(nav_frame, text=name, command=lambda n=name: self.controller.show_page(n)).pack(side=tk.LEFT,
                                                                                                      padx=5)



# --- Page: Vault ---
class VaultPage(tk.Frame):
    def __init__(self, parent, controller, page_names, email):
        super().__init__(parent)
        self.controller = controller
        self.page_names = page_names
        self.email = email

        self.passwords = load_generated_passwords()
        self.display_passwords()
        self.create_navbar(controller, page_names)

    def get_user_passwords(self):
        user_passwords = {}
        for label, data in self.passwords.items():

            if isinstance(data, dict):
                if 'email' in data and data['email'] == self.email:
                    user_passwords[label] = data
                else:
                    for subkey, subdata in data.items():
                        if isinstance(subdata, dict) and subdata.get('username') == self.email:
                            user_passwords[label] = subdata
        return user_passwords

    def display_passwords(self):
        for widget in self.winfo_children():
            if isinstance(widget, tk.Button) or isinstance(widget, tk.Label):
                widget.destroy()

        tk.Label(self, text="Vault - Stored Passwords").pack(pady=10)

        passwords = load_generated_passwords()
        user_passwords = passwords.get(self.email, {})

        for site_label, data in user_passwords.items():
            display_text = f"{site_label} ({data['username']})"
            tk.Button(
                self,
                text=display_text,
                command=lambda l=site_label: self.show_password(l)  # capture value here
            ).pack(pady=2)

    def show_password(self, label):
        passwords = load_generated_passwords()
        entry = passwords.get(self.email, {}).get(label)
        if not entry:
            return

        username = entry.get("username", "N/A")
        encrypted_pw = entry.get("password_enc")
        password = self.controller.fernet.decrypt(encrypted_pw.encode()).decode()

        popup = tk.Toplevel(self)
        popup.title(f"{label} Details")
        popup.geometry("300x150")

        tk.Label(popup, text=f"Username: {username}").pack(pady=5)
        tk.Label(popup, text=f"Password: {password}").pack(pady=5)

        def copy_to_clipboard():
            self.clipboard_clear()
            self.clipboard_append(password)
            self.update()
            messagebox.showinfo("Copied", "Password copied to clipboard!")

        tk.Button(popup, text="Copy Password", command=copy_to_clipboard).pack(pady=10)


    def create_navbar(self, controller, page_names):
        nav_frame = tk.Frame(self)
        nav_frame.pack(side=tk.BOTTOM, pady=10)
        for name in page_names:
            tk.Button(nav_frame, text=name, command=lambda n=name: controller.show_page(n)).pack(side=tk.LEFT, padx=5)


# --- Page: Settings ---
class SettingsPage(tk.Frame):
    def __init__(self, parent, controller, page_names):
        super().__init__(parent)
        self.controller = controller

        tk.Label(self, text="Settings Page").pack(pady=50)

        self.dark_mode_var = tk.BooleanVar(value=controller.dark_mode)
        dark_cb = tk.Checkbutton(self, text="Dark Mode", variable=self.dark_mode_var, command=self.toggle_dark_mode)
        dark_cb.pack(anchor='w', padx=20)

        self.create_navbar(controller, page_names)

    def toggle_dark_mode(self):
        self.controller.dark_mode = self.dark_mode_var.get()
        self.controller.apply_theme()

    def create_navbar(self, controller, page_names):
        nav_frame = tk.Frame(self)
        nav_frame.pack(side=tk.BOTTOM, pady=10)
        for name in page_names:
            tk.Button(nav_frame, text=name, command=lambda n=name: controller.show_page(n)).pack(side=tk.LEFT, padx=5)


# --- Page: Account ---
class AccountPage(tk.Frame):
    def __init__(self, parent, controller, page_names, email):
        super().__init__(parent)

        self.email = email
        self.controller = controller
        self.page_names = page_names

        tk.Label(self, text="Account Page").pack(pady=10)

        self.users = load_users()

        if isinstance(self.users, dict) and self.email in self.users:
            self.username = self.users[self.email].get("username", "")
        else:
            self.username = ""


        self.email_label = tk.Label(self, text=f"Email: {self.email}")
        self.email_label.pack(pady=10)

        self.greeting_message = tk.Label(self, text="", font=("Arial", 14))

        if self.username:
            self.greeting_message.config(text=f"Hello, {self.username}!")
        self.greeting_message.pack(pady=10)

        self.login_count = self.users[self.email].get("login_count", 0)
        self.login_count_label = tk.Label(self, text=f"Login count: {self.login_count}")
        self.login_count_label.pack(pady=5)

        if self.login_count >= 15:
            messagebox.showwarning("Password Update Required",
                                   "You have logged in 15 times. Please update your password.")
            self.new_pw_entry.focus_set()

        tk.Label(self, text="Change Password").pack(pady=10)

        self.new_pw_entry = tk.Entry(self, show="*")
        self.new_pw_entry.pack(pady=5)

        self.show_pw_var = tk.BooleanVar()
        self.show_pw_check = tk.Checkbutton(
            self, text="Show Password", variable=self.show_pw_var, command=self.toggle_password_visibility
        )
        self.show_pw_check.pack(pady=5)

        self.change_pw_button = tk.Button(self, text="Update Password", command=self.change_password)
        self.change_pw_button.pack(pady=10)

        if not self.username:
            self.username_entry = tk.Entry(self)
            self.username_entry.pack(pady=10)

            self.set_username_button = tk.Button(self, text="Set Username", command=self.set_username)
            self.set_username_button.pack(pady=5)

        self.logout_button = tk.Button(self, text="Logout", command=self.logout)
        self.logout_button.pack(side="bottom", pady=20)

        self.create_navbar(controller, page_names)

    def set_username(self):
        username = self.username_entry.get().strip()
        if username:
            save_user(self.email, self.users[self.email]["password"], username, is_hashed=True)
            self.username = username
            self.greeting_message.config(text=f"Hello, {self.username}!")
            self.username_entry.destroy()
            self.set_username_button.destroy()

    def logout(self):
        self.controller.authenticated = False
        self.controller.check_auth()

    def toggle_password_visibility(self):
        if self.show_pw_var.get():
            self.new_pw_entry.config(show="")  # show text
        else:
            self.new_pw_entry.config(show="*")  # hide text

    def change_password(self):
        new_pw = self.new_pw_entry.get().strip()

        if not new_pw:
            messagebox.showerror("Error", "Password cannot be empty.")
            return
        if len(new_pw) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long.")
            return

        save_user(self.email, new_pw, self.username, is_hashed=False)

        save_user(self.email, new_pw, self.username, is_hashed=False, login_count=self.login_count)
        self.login_count_label.config(text=f"Login count: {self.login_count}")

        messagebox.showinfo("Success", "Password updated successfully. Please log in again.")

        self.new_pw_entry.delete(0, tk.END)

        self.controller.authenticated = False
        self.controller.check_auth()

    def create_navbar(self, controller, page_names):
        nav_frame = tk.Frame(self)
        nav_frame.pack(side=tk.BOTTOM, pady=10)
        for name in page_names:
            tk.Button(nav_frame, text=name, command=lambda n=name: controller.show_page(n)).pack(side=tk.LEFT, padx=5)


# --- Main App ---
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Manager")
        self.geometry("800x600")
        self.dark_mode = False
        self.authenticated = False
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.version_label = tk.Label(self, text="App Version: V1.2", anchor="w")
        self.version_label.pack(side="left", padx=10, pady=10, anchor="sw")

        self.container = tk.Frame(self)
        self.container.pack(fill="both", expand=True)
        self.pages = {}
        self.page_names = ["Password Generator", "Vault", "Settings", "Account"]

        self.check_auth()

    def check_auth(self):
        auth_window = AuthPage(self, self)
        self.wait_window(auth_window)
        if self.authenticated:
            self.load_main_ui()
        else:
            self.destroy()

    def load_main_ui(self):
        for name in self.page_names:
            if name == "Password Generator":
                page = PasswordGeneratorPage(self.container, self, self.page_names)
            elif name == "Vault":
                page = VaultPage(self.container, self, self.page_names, self.email)
            elif name == "Settings":
                page = SettingsPage(self.container, self, self.page_names)
            elif name == "Account":
                page = AccountPage(self.container, self, self.page_names, self.email)

            self.pages[name] = page
            page.place(x=0, y=0, relwidth=1, relheight=1)

        self.apply_theme()
        self.show_page("Account")

    def show_page(self, page_name):
        if page_name == "Vault":
            self.pages[page_name].passwords = load_generated_passwords()
            self.pages[page_name].display_passwords()
        self.pages[page_name].tkraise()

    def generate_and_save_password(self, email):
        password = self.generate_random_password()
        save_generated_password(email, email, password)
        messagebox.showinfo("Password Generated", f"Password for {email} has been generated and saved.")

        self.show_page("Vault")

    def generate_random_password(self):
        length = 12
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(chars) for _ in range(length))

    def apply_theme(self):
        dark_bg = "#121212"
        dark_fg = "#e0e0e0"
        light_bg = "#f0f0f0"
        light_fg = "#000000"

        if self.dark_mode:
            bg = dark_bg
            fg = dark_fg
        else:
            bg = light_bg
            fg = light_fg

        self.configure(bg=bg)
        self.version_label.configure(bg=bg, fg=fg)

        def recursive_color(widget):
            try:
                widget.configure(bg=bg, fg=fg)
            except tk.TclError:
                try:
                    widget.configure(bg=bg)
                except tk.TclError:
                    pass
            for child in widget.winfo_children():
                recursive_color(child)

        recursive_color(self.container)

    def logout(self):
        self.authenticated = False
        self.check_auth()
        for page in self.pages.values():
            page.destroy()

        self.load_main_ui()

    def on_closing(self):
        self.destroy()


if __name__ == "__main__":
    app = App()
    app.mainloop()