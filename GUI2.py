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


# --- File I/O ---
def load_users():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}


def load_passwords(file_path="passwords.json"):
    if not os.path.exists(file_path):
        return {}
    with open(file_path, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def save_user(email, password, username=None, is_hashed=False):
    users = load_users()

    # Only hash if not already hashed
    if not is_hashed:
        password = hash_password(password)

    users[email] = {
        "password": password,
        "username": username if username else ""
    }

    with open(DATA_FILE, 'w') as f:
        json.dump(users, f, indent=4)


def load_generated_passwords():
    if os.path.exists(PASSWORDS_FILE):
        with open(PASSWORDS_FILE, 'r') as f:
            return json.load(f)
    return {}


def save_generated_password(label, email, password):
    passwords = load_generated_passwords()
    passwords[label] = {"username": email, "password": password}
    with open(PASSWORDS_FILE, 'w') as f:
        json.dump(passwords, f, indent=4)


def load_generated_passwords():
    if os.path.exists(PASSWORDS_FILE):
        with open(PASSWORDS_FILE, 'r') as f:
            return json.load(f)
    return {}


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
            messagebox.showinfo("Success", "Account created.")
            self.app.email = email  # Set the email after registration
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
            messagebox.showwarning("Missing Info",
                                   "Please generate a password and fill in Website/App Name and Username.")
            return

        save_generated_password(label, username, password_text)
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
    def __init__(self, parent, controller, page_names):
        super().__init__(parent)
        self.controller = controller
        self.page_names = page_names

        self.passwords = load_generated_passwords()
        self.display_passwords()
        self.create_navbar(controller, page_names)

    def display_passwords(self):
        for widget in self.winfo_children():
            if isinstance(widget, tk.Button) or isinstance(widget, tk.Label):
                widget.destroy()

        tk.Label(self, text="Vault - Stored Passwords").pack(pady=10)

        for label, data in self.passwords.items():
            if isinstance(data, dict) and "username" in data and "password" in data:
                display_text = f"{label} ({data['username']})"
                tk.Button(self, text=display_text, command=lambda l=label: self.show_password(l)).pack(pady=2)

    def show_password(self, label):
        entry = self.passwords[label]
        username = entry.get("username", "N/A")
        password = entry.get("password", "N/A")

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
                page = VaultPage(self.container, self, self.page_names)
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
        """Log out the user and show the login screen again."""
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