import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import random
import string
import itertools
import threading
import os
import hashlib
import urllib.request
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
PUNCTUATION = string.punctuation
ALL_CHARS = LOWERCASE + UPPERCASE + DIGITS + PUNCTUATION

PASSWORD_CHARS = ALL_CHARS
DEFAULT_PASSWORD_LENGTH = 20

def parse_mask(mask: str):
    charsets = []
    i = 0
    while i < len(mask):
        if mask[i] == '?':
            if i + 1 >= len(mask):
                raise ValueError("Некорректная маска: ? в конце строки")
            placeholder = mask[i + 1].lower()
            if placeholder == 'l':
                charsets.append(LOWERCASE)
            elif placeholder == 'u':
                charsets.append(UPPERCASE)
            elif placeholder == 'd':
                charsets.append(DIGITS)
            elif placeholder == 's':
                charsets.append(PUNCTUATION)
            elif placeholder == 'a':
                charsets.append(ALL_CHARS)
            else:
                raise ValueError(f"Неизвестный плейсхолдер: ?{placeholder}")
            i += 2
        else:
            charsets.append(mask[i])
            i += 1
    return charsets

def calculate_combinations(charsets):
    total = 1
    for cs in charsets:
        total *= len(cs)
    return total

def check_pwned_password(password: str):
    if not password:
        return None

    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    req = urllib.request.Request(url, headers={'User-Agent': 'PyGen-Password-Checker-v1'})

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            data = response.read().decode('utf-8')
        for line in data.splitlines():
            hash_suffix, count_str = line.strip().split(':')
            if hash_suffix == suffix:
                return int(count_str)
        return 0
    except Exception:
        return -1

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_file(input_path: str, output_path: str, password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)

    with open(input_path, 'rb') as fin:
        plaintext = fin.read()

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    with open(output_path, 'wb') as fout:
        fout.write(salt)
        fout.write(nonce)
        fout.write(ciphertext)

def try_decrypt_file_to_bytes(input_path: str, password: str) -> bytes | None:
    try:
        with open(input_path, 'rb') as fin:
            salt = fin.read(16)
            if len(salt) != 16:
                return None
            nonce = fin.read(12)
            if len(nonce) != 12:
                return None
            ciphertext = fin.read()

        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext
    except:
        return None

def decrypt_file(input_path: str, output_path: str, password: str):
    plaintext = try_decrypt_file_to_bytes(input_path, password)
    if plaintext is None:
        raise ValueError("Неверный пароль")
    with open(output_path, 'wb') as fout:
        fout.write(plaintext)

class PyGenGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PyGen — Генератор паролей, wordlist'ов и шифрование")
        self.geometry("1000x750")
        self.resizable(True, True)

        notebook = ttk.Notebook(self)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)

        tab_password = ttk.Frame(notebook)
        notebook.add(tab_password, text="Случайные пароли")

        tab_wordlist = ttk.Frame(notebook)
        notebook.add(tab_wordlist, text="Wordlist по маске")

        tab_check = ttk.Frame(notebook)
        notebook.add(tab_check, text="Проверка на утечки")

        tab_encrypt = ttk.Frame(notebook)
        notebook.add(tab_encrypt, text="Шифрование AES-256")

        self.setup_password_tab(tab_password)
        self.setup_wordlist_tab(tab_wordlist)
        self.setup_check_tab(tab_check)
        self.setup_encrypt_tab(tab_encrypt)

    def setup_password_tab(self, tab):
        frame = ttk.LabelFrame(tab, text="Настройки генерации")
        frame.pack(fill='x', padx=20, pady=20)

        info_label = ttk.Label(frame, text="Пароли генерируются из строчных, заглавных букв, цифр и спецсимволов (максимальная надёжность).")
        info_label.grid(row=0, column=0, columnspan=2, sticky='w', pady=5)

        ttk.Label(frame, text="Длина пароля:").grid(row=1, column=0, sticky='w', pady=5)
        self.length_var = tk.IntVar(value=DEFAULT_PASSWORD_LENGTH)
        ttk.Entry(frame, textvariable=self.length_var, width=10).grid(row=1, column=1, pady=5, sticky='w')

        ttk.Label(frame, text="Количество паролей:").grid(row=2, column=0, sticky='w', pady=5)
        self.count_var = tk.IntVar(value=10)
        ttk.Entry(frame, textvariable=self.count_var, width=10).grid(row=2, column=1, pady=5, sticky='w')

        btn_frame = ttk.Frame(tab)
        btn_frame.pack(pady=20)
        ttk.Button(btn_frame, text="Сгенерировать и показать", command=self.generate_passwords_show).pack(side='left', padx=10)
        ttk.Button(btn_frame, text="Сгенерировать и сохранить в файл", command=self.generate_passwords_file).pack(side='left', padx=10)

        self.password_output = scrolledtext.ScrolledText(tab, height=20)
        self.password_output.pack(fill='both', expand=True, padx=20, pady=10)

    def setup_wordlist_tab(self, tab):
        frame = ttk.LabelFrame(tab, text="Настройки wordlist")
        frame.pack(fill='x', padx=20, pady=20)

        ttk.Label(frame, text="Маска:").grid(row=0, column=0, sticky='nw', pady=5)
        self.mask_var = tk.StringVar()
        mask_entry = ttk.Entry(frame, textvariable=self.mask_var, width=60)
        mask_entry.grid(row=0, column=1, pady=5, sticky='w')

        explanation = ttk.Label(frame, text="""
Плейсхолдеры (заменители) в маске:
    ?l — строчная буква (a-z, 26 вариантов)
    ?u — заглавная буква (A-Z, 26 вариантов)
    ?d — цифра (0-9, 10 вариантов)
    ?s — спецсимвол (!@#$%^&*()_+-=[]{}|;':",./<>? и др., ~32 варианта)
    ?a — любой из вышеперечисленных символов (95 вариантов)

Фиксированные символы вводятся как есть (без ?).

Примеры масок:
    ?l?l?l?l?l?l       → все возможные 6-буквенные слова из строчных букв
    pass?u?d?s         → варианты вроде passA1!, passB2@ и т.д.
    admin?l?l?d?d      → admin + 2 строчные буквы + 2 цифры (например, adminab12)
    ?d?d/?d?d/?d?d?d?d → даты в формате ГГ/ММ/ДДДД (например, 01/01/2026)
    user?l?l?l?d       → user + 3 буквы + цифра

Маска может быть любой длины и комбинации.
""", justify='left', foreground="#555555")
        explanation.grid(row=1, column=0, columnspan=2, sticky='w', pady=15)

        self.combo_label = ttk.Label(frame, text="Комбинаций: — (введите маску и нажмите «Рассчитать»)")
        self.combo_label.grid(row=2, column=0, columnspan=2, sticky='w', pady=5)

        btn_frame = ttk.Frame(tab)
        btn_frame.pack(pady=20)
        ttk.Button(btn_frame, text="Рассчитать количество комбинаций", command=self.calculate_combos).pack(side='left', padx=10)
        ttk.Button(btn_frame, text="Сгенерировать wordlist в файл", command=self.generate_wordlist_file).pack(side='left', padx=10)

        self.progress = ttk.Progressbar(tab, mode='indeterminate')
        self.progress.pack(fill='x', padx=20, pady=10)
        self.status_label = ttk.Label(tab, text="Готов к работе")
        self.status_label.pack(pady=5)

    def setup_check_tab(self, tab):
        frame = ttk.LabelFrame(tab, text="Проверка пароля на утечки (HaveIBeenPwned)")
        frame.pack(fill='both', expand=True, padx=20, pady=20)

        info = ttk.Label(frame, text="Введите пароль для проверки.\n"
                                     "Проверка происходит безопасно (k-anonymity): полный пароль не передаётся на сервер.\n"
                                     "Если пароль найден хотя бы в одной утечке — его лучше не использовать.", 
                         justify='left', foreground="#333333")
        info.pack(anchor='w', pady=10)

        password_frame = ttk.Frame(frame)
        password_frame.pack(fill='x', pady=10)

        ttk.Label(password_frame, text="Пароль:").pack(side='left')
        self.check_password_var = tk.StringVar()
        self.check_entry = ttk.Entry(password_frame, textvariable=self.check_password_var, width=50, show='*')
        self.check_entry.pack(side='left', padx=10)

        self.show_password_var = tk.BooleanVar()
        ttk.Checkbutton(password_frame, text="Показать пароль", variable=self.show_password_var,
                        command=self.toggle_password_visibility).pack(side='left')

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=20)
        ttk.Button(btn_frame, text="Проверить на утечки", command=self.start_password_check).pack()

        self.check_result_label = ttk.Label(frame, text="Результат появится здесь", font=('Arial', 12, 'bold'))
        self.check_result_label.pack(pady=30)

        self.check_progress = ttk.Progressbar(frame, mode='indeterminate')
        self.check_progress.pack(fill='x', pady=10)

    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.check_entry.config(show='')
        else:
            self.check_entry.config(show='*')

    def start_password_check(self):
        password = self.check_password_var.get()
        if not password:
            messagebox.showwarning("Предупреждение", "Введите пароль для проверки")
            return

        self.check_result_label.config(text="Проверка... (запрос к API)", foreground="#555555")
        self.check_progress.start()

        def check():
            count = check_pwned_password(password)
            self.after(0, self.finish_password_check, count)

        threading.Thread(target=check, daemon=True).start()

    def finish_password_check(self, count):
        self.check_progress.stop()
        if count == -1:
            self.check_result_label.config(text="Ошибка: нет соединения с интернетом или сервер недоступен", foreground="red")
        elif count == 0:
            self.check_result_label.config(text="Пароль НЕ найден в известных утечках — можно использовать!", foreground="green")
        else:
            self.check_result_label.config(text=f"ВНИМАНИЕ! Пароль найден в {count:,} утечках — НЕ используйте его!", foreground="red")

    def setup_encrypt_tab(self, tab):
        info = ttk.Label(tab, text="AES-256-GCM — современное безопасное симметричное шифрование с аутентификацией.\n"
                                   "Файл шифруется целиком (подходит для файлов до нескольких сотен МБ).\n"
                                   "Пароль используется для вывода ключа через PBKDF2 (200 000 итераций).\n"
                                   "ВНИМАНИЕ: Забытый пароль = безвозвратная потеря данных!\n"
                                   "Требуется: pip install cryptography",
                         justify='left', foreground="#333333", font=('Arial', 10, 'bold'))
        info.pack(anchor='w', padx=20, pady=10)

        file_frame = ttk.LabelFrame(tab, text="Шифрование/дешифрование файлов")
        file_frame.pack(fill='both', expand=True, padx=20, pady=20)

        self.encrypt_file_path = None
        self.encrypt_file_label = ttk.Label(file_frame, text="Файл не выбран")
        self.encrypt_file_label.pack(pady=5)

        ttk.Button(file_frame, text="Выбрать файл", command=self.select_encrypt_file).pack(pady=10)

        ttk.Label(file_frame, text="Пароль:").pack(anchor='w', padx=10, pady=(10,0))
        self.encrypt_file_pass_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.encrypt_file_pass_var, width=50, show='*').pack(padx=10, pady=5)

        btn_file = ttk.Frame(file_frame)
        btn_file.pack(pady=10)
        ttk.Button(btn_file, text="Зашифровать файл (.enc)", command=self.encrypt_file_gui).pack(side='left', padx=10)
        ttk.Button(btn_file, text="Дешифровать файл", command=self.decrypt_file_gui).pack(side='left', padx=10)

        self.encrypt_progress = ttk.Progressbar(file_frame, mode='indeterminate')
        self.encrypt_progress.pack(fill='x', padx=10, pady=10)
        self.encrypt_status = ttk.Label(file_frame, text="Готов")
        self.encrypt_status.pack(pady=5)

    def select_encrypt_file(self):
        path = filedialog.askopenfilename(title="Выберите файл для шифрования или дешифрования")
        if path:
            self.encrypt_file_path = path
            size = os.path.getsize(path)
            self.encrypt_file_label.config(text=f"Выбран: {os.path.basename(path)} ({size:,} байт)")

    def encrypt_file_gui(self):
        if not self.encrypt_file_path or not self.encrypt_file_pass_var.get():
            messagebox.showwarning("Предупреждение", "Выберите файл и введите пароль")
            return
        output_path = filedialog.asksaveasfilename(defaultextension=".enc", title="Сохранить зашифрованный файл")
        if not output_path:
            return

        def run():
            self.encrypt_progress.start()
            self.encrypt_status.config(text="Шифрование...")
            try:
                encrypt_file(self.encrypt_file_path, output_path, self.encrypt_file_pass_var.get())
                self.after(0, lambda: self.encrypt_status.config(text="Готово!"))
                self.after(0, lambda: messagebox.showinfo("Успех", f"Файл успешно зашифрован:\n{output_path}"))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Ошибка", str(e)))
            finally:
                self.after(0, self.encrypt_progress.stop)

        threading.Thread(target=run, daemon=True).start()

    def decrypt_file_gui(self):
        if not self.encrypt_file_path or not self.encrypt_file_pass_var.get():
            messagebox.showwarning("Предупреждение", "Выберите файл и введите пароль")
            return
        output_path = filedialog.asksaveasfilename(title="Сохранить расшифрованный файл")
        if not output_path:
            return

        def run():
            self.encrypt_progress.start()
            self.encrypt_status.config(text="Дешифрование...")
            try:
                decrypt_file(self.encrypt_file_path, output_path, self.encrypt_file_pass_var.get())
                self.after(0, lambda: self.encrypt_status.config(text="Готово!"))
                self.after(0, lambda: messagebox.showinfo("Успех", f"Файл успешно расшифрован:\n{output_path}"))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Ошибка дешифрования", "Неверный пароль или повреждённый файл"))
            finally:
                self.after(0, self.encrypt_progress.stop)

        threading.Thread(target=run, daemon=True).start()

    def generate_passwords_show(self):
        try:
            length = self.length_var.get()
            count = self.count_var.get()

            if length < 1 or count < 1:
                raise ValueError("Длина и количество должны быть больше 0")

            self.password_output.delete(1.0, tk.END)
            for _ in range(count):
                password = ''.join(random.choice(PASSWORD_CHARS) for _ in range(length))
                self.password_output.insert(tk.END, password + '\n')
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def generate_passwords_file(self):
        try:
            length = self.length_var.get()
            count = self.count_var.get()

            if length < 1 or count < 1:
                raise ValueError("Длина и количество должны быть больше 0")

            file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
            if not file_path:
                return

            with open(file_path, 'w', encoding='utf-8') as f:
                for _ in range(count):
                    password = ''.join(random.choice(PASSWORD_CHARS) for _ in range(length))
                    f.write(password + '\n')

            messagebox.showinfo("Успех", f"Сгенерировано {count} паролей в файл:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def calculate_combos(self):
        mask = self.mask_var.get().strip()
        if not mask:
            messagebox.showwarning("Предупреждение", "Введите маску")
            return
        try:
            charsets = parse_mask(mask)
            total = calculate_combinations(charsets)
            self.combo_label.config(text=f"Комбинаций: {total:,}")
            if total > 1_000_000:
                messagebox.showwarning("Внимание", f"Очень большой wordlist ({total:,} строк)!\nЭто может занять много времени и места на диске.")
        except Exception as e:
            messagebox.showerror("Ошибка в маске", str(e))

    def generate_wordlist_file(self):
        mask = self.mask_var.get().strip()
        if not mask:
            messagebox.showwarning("Предупреждение", "Введите маску")
            return

        try:
            charsets = parse_mask(mask)
            total = calculate_combinations(charsets)
            if total == 0:
                raise ValueError("Маска даёт 0 комбинаций")

            file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")],
                                                     title="Выберите файл для сохранения wordlist")
            if not file_path:
                return

            def generate():
                self.progress.start()
                self.status_label.config(text=f"Генерация {total:,} строк... (это может занять время)")
                try:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        for combo in itertools.product(*charsets):
                            word = ''.join(combo)
                            f.write(word + '\n')
                    self.status_label.config(text=f"Готово! Записано {total:,} строк в {os.path.basename(file_path)}")
                    messagebox.showinfo("Успех", f"Wordlist успешно создан:\n{file_path}\nСтрок: {total:,}")
                except Exception as e:
                    messagebox.showerror("Ошибка при генерации", str(e))
                finally:
                    self.progress.stop()

            threading.Thread(target=generate, daemon=True).start()

        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

if __name__ == "__main__":
    app = PyGenGUI()
    app.mainloop()
