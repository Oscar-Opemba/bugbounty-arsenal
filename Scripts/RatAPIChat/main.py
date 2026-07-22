import requests
import json
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import os
import csv

import ratcore
import session_store
from ratcore import RateLimiter, build_request, BodyParseError

# ---- Persistence: user config dir, owner-only perms (NOT world-readable /tmp) ----
CONFIG_DIR = session_store.config_dir()
LAST_SESSION_FILE = CONFIG_DIR / "last_session.json"
PREFERENCES_FILE = CONFIG_DIR / "preferences.json"
BURP_CERT_PATH = ""  # set via "Import Burp Cert" or preferences

# In-memory request history for the current session (may hold live tokens).
history_entries = []

# ---- Network / throttle defaults ----
REQUEST_TIMEOUT = 30          # seconds; stops a slow/tarpitting host hanging the UI
DEFAULT_RATE_LIMIT = 1.0      # requests/sec used when fuzzing
rate_limiter = RateLimiter(DEFAULT_RATE_LIMIT)

# Load the pre-populated fuzzing lists from the PREPOPLISTS folder
def load_prepopulated_lists():
    prepopulated_lists = {}
    prepop_folder = "PREPOPLISTS"
    if not os.path.exists(prepop_folder):
        os.makedirs(prepop_folder)
        return prepopulated_lists

    for filename in os.listdir(prepop_folder):
        if filename.endswith(".txt"):
            with open(os.path.join(prepop_folder, filename), 'r') as f:
                fuzz_values = f.read().splitlines()
                prepopulated_lists[filename] = fuzz_values
    return prepopulated_lists

def update_fuzz_ui():
    prepopulated_lists = load_prepopulated_lists()

    # Clear the previous entries
    fuzz_text.delete("1.0", tk.END)
    fuzz_listbox.delete(0, tk.END)

    # Populate the Listbox with the names of the available pre-populated fuzzing lists
    for list_name in prepopulated_lists:
        fuzz_listbox.insert(tk.END, list_name)

    # Also provide an option to let users enter their own fuzz values
    fuzz_text.insert(tk.END, 'Enter custom fuzz values (one per line), or select a pre-populated list above.')

def use_prepopulated_fuzz_list():
    selected_index = fuzz_listbox.curselection()
    if not selected_index:
        return

    list_name = fuzz_listbox.get(selected_index[0])
    prepopulated_lists = load_prepopulated_lists()
    fuzz_values = prepopulated_lists.get(list_name, [])

    # Populate the fuzz input field with the selected list
    fuzz_text.delete("1.0", tk.END)
    for value in fuzz_values:
        fuzz_text.insert(tk.END, value + "\n")

def fuzz_parameters():
    """
    Send one request per fuzz value, THROTTLED by the rate limiter, after an
    explicit confirmation showing exactly where and how much traffic will go.

    (The original tool had a rate limiter that was silently bypassed by a
    duplicate function definition — fuzzing fired as fast as the network allowed.)
    """
    values = [v for v in fuzz_text.get("1.0", tk.END).strip().splitlines() if v.strip()]
    if not values:
        messagebox.showinfo("Nothing to fuzz", "Enter one or more fuzz values first.")
        return

    # Apply the user-configured rate (requests/sec).
    rate_limiter.set_rate(rate_entry.get())
    target = ratcore.host_of(base_url_entry.get() + url_entry.get()) or "(unset)"
    est = len(values) / rate_limiter.rate
    proceed = messagebox.askokcancel(
        "Confirm fuzzing",
        f"Send {len(values)} requests to '{target}'\n"
        f"at {rate_limiter.rate:g} req/sec (~{est:.0f}s).\n\n"
        f"Only do this against targets you are authorized to test. Proceed?",
        icon="warning",
    )
    if not proceed:
        return

    for value in values:
        rate_limiter.wait()
        perform_request(fuzz_value=value)

def load_preferences():
    """Load preferences if they exist (no secrets stored here)."""
    prefs = session_store.load_json(PREFERENCES_FILE, default={})
    if not prefs:
        return
    proxy_entry.insert(0, prefs.get("default_proxy", ""))
    cert = prefs.get("burp_cert_path", "")
    if cert and os.path.exists(cert):
        global BURP_CERT_PATH
        BURP_CERT_PATH = cert

def save_preferences():
    prefs = {
        "default_proxy": proxy_entry.get(),
        "burp_cert_path": BURP_CERT_PATH,
    }
    session_store.save_json(prefs, PREFERENCES_FILE)
    messagebox.showinfo("Saved", f"Preferences saved to {PREFERENCES_FILE}")

def import_burp_cert():
    global BURP_CERT_PATH
    cert_path = filedialog.askopenfilename(title="Select Burp Suite Certificate", filetypes=[("PEM files", "*.pem")])
    if cert_path:
        BURP_CERT_PATH = cert_path
        messagebox.showinfo("Certificate Imported", f"Burp Suite certificate imported from:\n{cert_path}")

def import_swagger():
    file_path = filedialog.askopenfilename(title="Select Swagger/OpenAPI JSON", filetypes=[("JSON files", "*.json")])
    if not file_path:
        return
    try:
        with open(file_path, 'r') as f:
            swagger = json.load(f)
        endpoints, endpoint_data = ratcore.parse_swagger_endpoints(swagger)
        if endpoints:
            top = tk.Toplevel(root)
            top.title("Swagger Endpoints")
            lb = tk.Listbox(top, width=80, height=20)
            lb.pack(padx=10, pady=10)
            for ep in endpoints:
                lb.insert(tk.END, ep)
            def use_selected():
                selected = lb.curselection()
                if selected:
                    key = lb.get(selected[0])
                    method, endpoint = key.split(" ", 1)
                    method_var.set(method)
                    url_entry.delete(0, tk.END)
                    url_entry.insert(0, endpoint)
                    if 'requestBody' in endpoint_data[key]:
                        content = endpoint_data[key]['requestBody'].get('content', {})
                        json_schema = content.get('application/json', {}).get('example')
                        if not json_schema:
                            json_schema = content.get('application/json', {}).get('schema')
                        if json_schema:
                            try:
                                if isinstance(json_schema, dict):
                                    formatted = json.dumps(json_schema, indent=2)
                                else:
                                    formatted = str(json_schema)
                                body_text.delete("1.0", tk.END)
                                body_text.insert(tk.END, formatted)
                            except Exception as e:
                                print("Schema parse error:", e)
            tk.Button(top, text="Use Selected", command=use_selected).pack(pady=5)
        else:
            messagebox.showinfo("No Endpoints", "No paths found in Swagger file.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to parse Swagger file:\n{e}")

def save_session():
    file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
    if not file_path:
        return
    # Secrets are redacted unless the user explicitly opts in.
    include = messagebox.askyesno(
        "Include secrets?",
        "Include authentication tokens/passwords in the saved file?\n\n"
        "Choose No (recommended) to redact them. Choosing Yes writes live "
        "credentials to disk (the file is created owner-only, 0600).",
    )
    session_store.save_history(history_entries, file_path, redact=not include)
    messagebox.showinfo("Saved", f"Session saved to {os.path.basename(file_path)}"
                                 + ("" if include else " (secrets redacted)"))

def load_session():
    """Load the last session file and populate the history."""
    loaded_entries = session_store.load_history(LAST_SESSION_FILE)
    history_entries.clear()
    history_listbox.delete(0, tk.END)
    for entry in loaded_entries:
        history_entries.append(entry)
        history_listbox.insert(tk.END, f"{entry['method']} {entry['url']} [{entry['status_code']}]")
    if loaded_entries:
        load_history_from_session(loaded_entries[-1])

def load_history_from_session(entry):
    """Populate the UI with data from a session entry."""
    base_url, endpoint = ratcore.split_url(entry["url"])

    # Update the UI fields with the split base URL and endpoint
    base_url_entry.delete(0, tk.END)
    base_url_entry.insert(0, base_url)
    url_entry.delete(0, tk.END)
    url_entry.insert(0, endpoint)

    # Populate the other fields with the selected entry's data
    token_entry.delete(0, tk.END)
    token_entry.insert(0, entry["auth_token"])
    method_var.set(entry["method"])
    content_type_var.set(entry.get("content_type", "JSON"))
    proxy_entry.delete(0, tk.END)
    proxy_entry.insert(0, entry["proxy"])
    body_text.delete("1.0", tk.END)
    body_text.insert(tk.END, entry["body"])
    response_text.delete("1.0", tk.END)
    response_text.insert(tk.END, f"Status Code: {entry['status_code']}\n\n{entry['response']}")

def export_to_csv():
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if not file_path:
        return
    with open(file_path, 'w', newline='') as csvfile:
        fieldnames = ['method', 'url', 'status_code', 'body', 'response']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for entry in history_entries:
            writer.writerow({k: entry.get(k, '') for k in fieldnames})
    messagebox.showinfo("Exported", "History exported to CSV")

def perform_request(fuzz_value=None):
    base_url = base_url_entry.get()
    endpoint = url_entry.get()
    auth_token = token_entry.get()
    method = method_var.get()
    proxy_url = proxy_entry.get()
    body_input = body_text.get("1.0", tk.END).strip()
    content_type = content_type_var.get()

    proxies = None
    verify_cert = True  # verify TLS by default; only relax to a pinned Burp cert
    if proxy_url:
        proxies = {"http": proxy_url, "https": proxy_url}
        if BURP_CERT_PATH and os.path.exists(BURP_CERT_PATH):
            verify_cert = BURP_CERT_PATH

    # Build request kwargs with the tested pure core.
    try:
        req = build_request(
            method, base_url, endpoint,
            auth_type=auth_type_var.get(), token=auth_token,
            username=username_entry.get(), password=password_entry.get(),
            content_type=content_type, body=body_input, fuzz_value=fuzz_value,
        )
    except BodyParseError as e:
        messagebox.showerror("Error", str(e))
        return

    full_url = req["full_url"]
    body_sent = body_input.replace("FUZZ", fuzz_value) if fuzz_value else body_input
    try:
        response = requests.request(
            method, full_url, headers=req["headers"], data=req["data"],
            json=req["json"], proxies=proxies, verify=verify_cert,
            timeout=REQUEST_TIMEOUT,
        )
        history_data = {
            "url": full_url,
            "auth_token": auth_token,
            "method": method,
            "proxy": proxy_url,
            "body": body_sent,
            "status_code": response.status_code,
            "response": response.text,
            "content_type": content_type,
        }
        history_entries.append(history_data)
        history_listbox.insert(tk.END, f"{method} {full_url} [{response.status_code}]")

        # Auto-save the session — SECRETS REDACTED, owner-only file in config dir.
        session_store.save_history(history_entries, LAST_SESSION_FILE, redact=True)

        response_text.delete("1.0", tk.END)
        response_text.insert(tk.END, f"Status Code: {response.status_code}\n\n{response.text}")
    except requests.exceptions.Timeout:
        messagebox.showerror("Timeout", f"Request to {full_url} timed out after {REQUEST_TIMEOUT}s.")
    except requests.exceptions.RequestException as e:
        messagebox.showerror("Error", f"Request failed: {e}")

def load_history(event):
    selected_index = history_listbox.curselection()
    if not selected_index:
        return

    entry = history_entries[selected_index[0]]

    base_url, endpoint = ratcore.split_url(entry["url"])

    # Update the UI fields with the split base URL and endpoint
    base_url_entry.delete(0, tk.END)
    base_url_entry.insert(0, base_url)
    url_entry.delete(0, tk.END)
    url_entry.insert(0, endpoint)

    # Populate the other fields with the selected entry's data
    token_entry.delete(0, tk.END)
    token_entry.insert(0, entry["auth_token"])
    method_var.set(entry["method"])
    content_type_var.set(entry.get("content_type", "JSON"))
    proxy_entry.delete(0, tk.END)
    proxy_entry.insert(0, entry["proxy"])
    body_text.delete("1.0", tk.END)
    body_text.insert(tk.END, entry["body"])
    response_text.delete("1.0", tk.END)
    response_text.insert(tk.END, f"Status Code: {entry['status_code']}\n\n{entry['response']}")

# GUI setup
root = tk.Tk()
root.title("API Request Tool")

# Menu bar
menu_bar = tk.Menu(root)
file_menu = tk.Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Save Session", command=save_session)
file_menu.add_command(label="Load Session", command=load_session)
file_menu.add_command(label="Export to CSV", command=export_to_csv)
file_menu.add_command(label="Import Burp Cert", command=import_burp_cert)
file_menu.add_command(label="Import Swagger", command=import_swagger)
file_menu.add_command(label="Save Preferences", command=save_preferences)
menu_bar.add_cascade(label="File", menu=file_menu)
root.config(menu=menu_bar)
# Function to update the UI fields based on the selected authentication type
def update_auth_ui(*args):
    auth_type = auth_type_var.get()

    # Hide all authentication-related fields initially
    username_label.grid_forget()
    username_entry.grid_forget()
    password_label.grid_forget()
    password_entry.grid_forget()
    token_label.grid_forget()
    token_entry.grid_forget()

    # Show the appropriate fields based on the selected auth type
    if auth_type == "Basic":
        # Place the username and password on the same row (row 4)
        username_label.grid(row=4, column=0, sticky="w", padx=5, pady=5)
        username_entry.grid(row=4, column=1, sticky="ew", padx=5, pady=5)
        password_label.grid(row=4, column=2, sticky="w", padx=5, pady=5)
        password_entry.grid(row=4, column=3, sticky="ew", padx=5, pady=5)
    elif auth_type == "Bearer" or auth_type == "OAuth 2.0":
        token_label.grid(row=3, column=0, sticky="w", padx=5, pady=5)
        token_entry.grid(row=3, column=1, columnspan=2, sticky="ew", padx=5, pady=5)


# UI fields
tk.Label(root, text="Base URL:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
base_url_entry = tk.Entry(root, width=80)
base_url_entry.grid(row=0, column=1, columnspan=2, sticky="ew", padx=5, pady=5)

tk.Label(root, text="API Endpoint:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
url_entry = tk.Entry(root, width=80)
url_entry.grid(row=1, column=1, columnspan=2, sticky="ew", padx=5, pady=5)


tk.Label(root, text="Authentication Type:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
auth_type_var = tk.StringVar(value="Bearer")
auth_type_var.trace_add("write", update_auth_ui)  # Update UI when authentication type changes
tk.OptionMenu(root, auth_type_var, "Basic", "Bearer", "OAuth 2.0").grid(row=2, column=1, sticky="ew", padx=5, pady=5)

# Labels and entries for different authentication types
username_label = tk.Label(root, text="Username:")
username_entry = tk.Entry(root, width=80)

password_label = tk.Label(root, text="Password:")
password_entry = tk.Entry(root, width=80, show="*")

token_label = tk.Label(root, text="Auth Token:")
token_entry = tk.Entry(root, width=80, show="*")

# Initially show fields for Bearer/OAuth 2.0 authentication
update_auth_ui()

tk.Label(root, text="Method:").grid(row=5, column=0, sticky="w", padx=5, pady=5)
method_var = tk.StringVar(value="GET")
tk.OptionMenu(root, method_var, "GET", "POST", "PUT", "DELETE").grid(row=5, column=1, sticky="ew", padx=5, pady=5)

tk.Label(root, text="Content Type:").grid(row=6, column=0, sticky="w", padx=5, pady=5)
content_type_var = tk.StringVar(value="JSON")
tk.OptionMenu(root, content_type_var, "JSON", "Form Data").grid(row=6, column=1, sticky="ew", padx=5, pady=5)

tk.Label(root, text="Proxy URL:").grid(row=7, column=0, sticky="w", padx=5, pady=5)
proxy_entry = tk.Entry(root, width=80)
proxy_entry.grid(row=7, column=1, columnspan=2, sticky="ew", padx=5, pady=5)

tk.Label(root, text="Request Body:").grid(row=8, column=0, sticky="nw", padx=5, pady=5)
body_text = scrolledtext.ScrolledText(root, height=5, width=60)
body_text.grid(row=8, column=1, columnspan=2, sticky="ew", padx=5, pady=5)

tk.Button(root, text="Send Request", command=perform_request).grid(row=9, column=1, pady=5, sticky="ew", padx=5)

# Fuzz rate control (requests/sec) — actually enforced now.
tk.Label(root, text="Fuzz rate (req/sec):").grid(row=10, column=0, sticky="w", padx=5, pady=5)
rate_entry = tk.Entry(root, width=10)
rate_entry.insert(0, str(DEFAULT_RATE_LIMIT))
rate_entry.grid(row=10, column=1, sticky="w", padx=5, pady=5)

tk.Label(root, text="Fuzz Values (use 'FUZZ' in body):").grid(row=11, column=0, sticky="nw", padx=5, pady=5)
fuzz_text = scrolledtext.ScrolledText(root, height=5, width=30)
fuzz_text.grid(row=11, column=1, sticky="nw", padx=5, pady=5)
tk.Button(root, text="Fuzz Parameters", command=fuzz_parameters).grid(row=11, column=2, pady=5, sticky="n", padx=5)

# Prepopulated fuzz lists (from ./PREPOPLISTS/*.txt) — previously referenced a
# widget that was never created, so the feature NameError'd. Now wired up.
tk.Label(root, text="Prepopulated fuzz lists:").grid(row=10, column=3, sticky="w", padx=5)
tk.Button(root, text="Load selected list", command=use_prepopulated_fuzz_list).grid(row=9, column=3, sticky="ew", padx=5)
fuzz_listbox = tk.Listbox(root, height=5, width=26)
fuzz_listbox.grid(row=11, column=3, sticky="nw", padx=5, pady=5)

tk.Label(root, text="History:").grid(row=12, column=0, sticky="nw", padx=5, pady=5)
history_listbox = tk.Listbox(root, height=10, width=50)
history_listbox.grid(row=12, column=1, sticky="nw", padx=5, pady=5)
history_listbox.bind('<<ListboxSelect>>', load_history)

tk.Label(root, text="Response:").grid(row=12, column=2, sticky="nw", padx=5, pady=5)
response_text = scrolledtext.ScrolledText(root, height=10, width=50)
response_text.grid(row=12, column=2, sticky="ne", padx=5, pady=5)

# Make columns responsive to resizing
root.grid_columnconfigure(1, weight=1)
root.grid_columnconfigure(2, weight=1)

# Load preferences and previous session
load_preferences()
load_session()      # Load the session on startup
update_fuzz_ui()    # Populate the prepopulated-fuzz-list picker

for entry in history_entries:
    history_listbox.insert(tk.END, f"{entry['method']} {entry['url']} [{entry['status_code']}]")

root.mainloop()
