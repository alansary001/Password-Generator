import random
import string
import tkinter as tk
from tkinter import messagebox, filedialog
import os

# Function to generate a password
def generate_password(length=8, use_upper=True, use_lower=True, use_digits=True, use_symbols=True):
    if length < 4:
        raise ValueError("Password length should be at least 4 to include all selected character types.")

    upper = string.ascii_uppercase if use_upper else ''
    lower = string.ascii_lowercase if use_lower else ''
    digits = string.digits if use_digits else ''
    symbols = string.punctuation if use_symbols else ''
    
    all_characters = upper + lower + digits + symbols

    if not all_characters:
        raise ValueError("No character types selected! Please choose at least one option.")
    
    # Ensure at least one character from each selected character set
    password = []
    if use_upper:
        password.append(random.choice(upper))
    if use_lower:
        password.append(random.choice(lower))
    if use_digits:
        password.append(random.choice(digits))
    if use_symbols:
        password.append(random.choice(symbols))

    remaining_length = length - len(password)
    password += [random.choice(all_characters) for _ in range(remaining_length)]
    
    random.shuffle(password)
    return ''.join(password)

# Function to check password strength
def check_password_strength(password):
    strength = 0
    if len(password) >= 8:
        strength += 1
    if any(char.islower() for char in password):
        strength += 1
    if any(char.isupper() for char in password):
        strength += 1
    if any(char.isdigit() for char in password):
        strength += 1
    if any(char in string.punctuation for char in password):
        strength += 1
    
    # Strength classification
    if strength == 5:
        return "Strong"
    elif 3 <= strength < 5:
        return "Medium"
    else:
        return "Weak"

# Function to save the password to a file
def save_password_to_file(password, filename='password_history.txt'):
    with open(filename, 'a') as file:
        file.write(password + '\n')
    messagebox.showinfo("Success", "Password saved to file successfully.")

# Function to load and display password history
def load_password_history(filename='password_history.txt'):
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            history = file.read()
        return history
    else:
        return "No password history found."

# Function to handle GUI button click to generate password
def on_generate_password():
    try:
        length = int(length_entry.get())
        use_upper = upper_var.get()
        use_lower = lower_var.get()
        use_digits = digits_var.get()
        use_symbols = symbols_var.get()
        
        password = generate_password(length, use_upper, use_lower, use_digits, use_symbols)
        password_entry.delete(0, tk.END)
        password_entry.insert(0, password)
        
        strength = check_password_strength(password)
        strength_label.config(text=f"Password Strength: {strength}")

    except ValueError as e:
        messagebox.showerror("Error", str(e))

# Function to save generated password
def on_save_password():
    password = password_entry.get()
    if password:
        save_password_to_file(password)
    else:
        messagebox.showerror("Error", "No password to save!")

# Function to view password history
def on_view_history():
    history = load_password_history()
    history_window = tk.Toplevel(root)
    history_window.title("Password History")
    history_text = tk.Text(history_window, wrap=tk.WORD)
    history_text.insert(tk.END, history)
    history_text.pack(expand=True, fill=tk.BOTH)

# Function to clear the history
def on_clear_history():
    if os.path.exists('password_history.txt'):
        os.remove('password_history.txt')
        messagebox.showinfo("Success", "Password history cleared.")
    else:
        messagebox.showerror("Error", "No password history to clear.")

# Function to browse and set the password history file location
def on_browse_file():
    file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file:
        save_password_to_file(file)

# Setting up the GUI using Tkinter
root = tk.Tk()
root.title("Password Generator")

# Length label and entry
tk.Label(root, text="Password Length:").grid(row=0, column=0, padx=10, pady=10)
length_entry = tk.Entry(root)
length_entry.grid(row=0, column=1, padx=10, pady=10)

# Checkboxes for character types
upper_var = tk.BooleanVar(value=True)
lower_var = tk.BooleanVar(value=True)
digits_var = tk.BooleanVar(value=True)
symbols_var = tk.BooleanVar(value=True)

tk.Checkbutton(root, text="Include Uppercase Letters", variable=upper_var).grid(row=1, column=0, columnspan=2, sticky=tk.W)
tk.Checkbutton(root, text="Include Lowercase Letters", variable=lower_var).grid(row=2, column=0, columnspan=2, sticky=tk.W)
tk.Checkbutton(root, text="Include Digits", variable=digits_var).grid(row=3, column=0, columnspan=2, sticky=tk.W)
tk.Checkbutton(root, text="Include Symbols", variable=symbols_var).grid(row=4, column=0, columnspan=2, sticky=tk.W)

# Generate password button
generate_button = tk.Button(root, text="Generate Password", command=on_generate_password)
generate_button.grid(row=5, column=0, columnspan=2, pady=10)

# Password entry (to display generated password)
password_entry = tk.Entry(root, width=40)
password_entry.grid(row=6, column=0, columnspan=2, padx=10, pady=10)

# Password strength label
strength_label = tk.Label(root, text="Password Strength: ")
strength_label.grid(row=7, column=0, columnspan=2)

# Save password button
save_button = tk.Button(root, text="Save Password", command=on_save_password)
save_button.grid(row=8, column=0, pady=10)

# View history button
history_button = tk.Button(root, text="View Password History", command=on_view_history)
history_button.grid(row=8, column=1, pady=10)

# Clear history button
clear_button = tk.Button(root, text="Clear History", command=on_clear_history)
clear_button.grid(row=9, column=0, pady=10)

# Browse button to set the file location for saving passwords
browse_button = tk.Button(root, text="Browse to Save Passwords", command=on_browse_file)
browse_button.grid(row=9, column=1, pady=10)

# Run the Tkinter event loop
root.mainloop()
