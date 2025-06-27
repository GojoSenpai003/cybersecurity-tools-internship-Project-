import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter import ttk
from zxcvbn import zxcvbn
import itertools

# --- Leetspeak Generator ---
def leetspeak_variations(word):
    replacements = {
        'a': ['a', '@', '4'],
        'e': ['e', '3'],
        'i': ['i', '1', '!'],
        'o': ['o', '0'],
        's': ['s', '$', '5'],
        't': ['t', '7'],
    }

    variations = ['']
    for char in word.lower():
        new_variations = []
        if char in replacements:
            for var in variations:
                for rep in replacements[char]:
                    new_variations.append(var + rep)
        else:
            for var in variations:
                new_variations.append(var + char)
        variations = new_variations
    return list(set(variations))

# --- Password Strength Analyzer ---
def check_password_strength():
    pwd = password_entry.get()
    if not pwd:
        messagebox.showwarning("Warning", "Please enter a password.")
        return
    result = zxcvbn(pwd)
    score = result['score']
    crack_time = result['crack_times_display']['offline_fast_hashing_1e10_per_second']
    warning = result['feedback']['warning']
    suggestions = "\n".join(result['feedback']['suggestions'])

    output = f"🔐 Password Score (0-4): {score}\n🕒 Crack Time: {crack_time}"
    if warning:
        output += f"\n⚠️ Warning: {warning}"
    if suggestions:
        output += f"\n💡 Suggestions:\n{suggestions}"

    result_text.config(state="normal")
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, output)
    result_text.config(state="disabled")

# --- Wordlist Generator ---
def generate_wordlist_gui():
    name = name_entry.get()
    dob = dob_entry.get()
    pet = pet_entry.get()

    if not (name or dob or pet):
        messagebox.showwarning("Input Missing", "Please enter at least one input.")
        return

    base_words = [name, dob, pet]
    suffixes = ["123", "@123", "!", "#", "2024", "2025"]
    wordlist = []

    for word in base_words:
        if word:
            variants = leetspeak_variations(word)
            for var in variants:
                wordlist.append(var)
                for suf in suffixes:
                    wordlist.append(var + suf)

    wordlist = list(set(wordlist))  # remove duplicates

    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, "w") as f:
            for word in wordlist:
                f.write(word + "\n")
        messagebox.showinfo("Success", f"Wordlist saved with {len(wordlist)} words.")

# --- GUI Layout ---
root = tk.Tk()
root.title("Cyber Security Toolkit")
root.geometry("600x500")
root.resizable(False, False)

# --- Notebook Tabs ---
notebook = ttk.Notebook(root)
frame1 = tk.Frame(notebook)
frame2 = tk.Frame(notebook)
notebook.add(frame1, text="🔐 Password Analyzer")
notebook.add(frame2, text="📝 Wordlist Generator")
notebook.pack(expand=True, fill="both")

# --- Frame 1: Password Analyzer UI ---
tk.Label(frame1, text="Enter Password:", font=("Arial", 12)).pack(pady=10)
password_entry = tk.Entry(frame1, width=40, show='*')
password_entry.pack()

tk.Button(frame1, text="Analyze", command=check_password_strength).pack(pady=10)

result_text = tk.Text(frame1, height=10, width=70, state="disabled")
result_text.pack(pady=10)

# --- Frame 2: Wordlist Generator UI ---
tk.Label(frame2, text="Enter Your Name:").pack(pady=5)
name_entry = tk.Entry(frame2, width=30)
name_entry.pack()

tk.Label(frame2, text="Enter Your DOB (e.g., 1999):").pack(pady=5)
dob_entry = tk.Entry(frame2, width=30)
dob_entry.pack()

tk.Label(frame2, text="Enter Pet Name:").pack(pady=5)
pet_entry = tk.Entry(frame2, width=30)
pet_entry.pack()

tk.Button(frame2, text="Generate Wordlist", command=generate_wordlist_gui).pack(pady=20)

# --- Launch App ---
root.mainloop()
