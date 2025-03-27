import tkinter as tk
import secrets
import string
from tkinter import messagebox


class PasswordGeneratorPage(tk.Frame):
    def __init__(self, parent, controller, page_names):
        super().__init__(parent)
        self.controller = controller

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

        # Navigation buttons
        y_offset = 10
        for page_name in page_names:
            btn = tk.Button(self, text=page_name, command=lambda p=page_name: self.controller.show_page(p))
            btn.place(x=10, y=y_offset)
            y_offset += 40

    def generate_password(self):
        try:
            length = int(self.length_entry.get())
            password = self._generate_password(length, self.use_letters.get(), self.use_numbers.get(),
                                               self.use_specials.get())
            self.result_label.config(text=f"Generated: {password}")
        except ValueError as e:
            self.result_label.config(text=str(e))

    def _generate_password(self, length, use_letters, use_numbers, use_specials):
        if length < 8 or length > 20:
            raise ValueError("Password length must be between 8 and 20 characters.")

        character_pool = ""
        if use_letters:
            character_pool += string.ascii_letters
        if use_numbers:
            character_pool += string.digits
        if use_specials:
            character_pool += string.punctuation

        if not character_pool:
            raise ValueError("At least one character type must be selected.")

        return ''.join(secrets.choice(character_pool) for _ in range(length))


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Manager")
        self.geometry("800x600")

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.container = tk.Frame(self)
        self.container.pack(fill="both", expand=True)

        self.pages = {}

        page_data = [
            "Password Generator",
            "Vault",
            "Settings",
            "Account"
        ]

        for page_name in page_data:
            if page_name == "Password Generator":
                self.pages[page_name] = PasswordGeneratorPage(self.container, self, page_data)
            else:
                self.pages[page_name] = Page(self.container, self, page_name, page_data)

        for page in self.pages.values():
            page.place(x=0, y=0, relwidth=1, relheight=1)

        self.current_page = "Password Generator"
        self.show_page(self.current_page)

    def show_page(self, page_name):
        self.pages[page_name].tkraise()
        self.current_page = page_name

    def on_closing(self):
        if messagebox.askyesno(title="Quit?", message="Do you really want to quit?"):
            self.destroy()


class Page(tk.Frame):
    def __init__(self, parent, controller, text, page_names):
        super().__init__(parent)
        self.controller = controller

        # Buttons for navigation (on the top left side)
        y_offset = 10
        for page_name in page_names:
            btn = tk.Button(self, text=page_name, command=lambda p=page_name: self.controller.show_page(p))
            btn.place(x=10, y=y_offset)
            y_offset += 40


if __name__ == "__main__":
    app = App()
    app.mainloop()
