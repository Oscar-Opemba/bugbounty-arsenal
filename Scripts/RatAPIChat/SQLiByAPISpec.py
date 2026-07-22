"""
SQLiByAPISpec — GUI SQL-injection probe driven by an OpenAPI/Swagger spec.

Hardened: bounded worker pool (was one unbounded thread per path), thread-safe
GUI updates via a queue (tkinter is not thread-safe), request timeouts, a
confirmation gate before firing, and DBMS-signature-based detection instead of
the old "error" substring check.

Authorized testing only. See ../../LEGAL.md.
"""
import json
import queue
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

import sqli_core

MAX_WORKERS = 8          # bound concurrency (was unbounded thread-per-endpoint)
REQUEST_TIMEOUT = 15     # seconds
DEFAULT_PARAM = "param"

# Worker threads never touch tkinter directly; they push messages here and the
# main thread drains them on a timer.
_msgs: "queue.Queue[str]" = queue.Queue()


def load_openapi_spec(file_path):
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        messagebox.showerror("Error", f"Could not load OpenAPI spec:\n{e}")
        return None


def test_endpoint(base_url, path, payloads, param=DEFAULT_PARAM):
    for payload in payloads:
        url = sqli_core.build_test_url(base_url, path, param, payload)
        try:
            resp = requests.get(url, timeout=REQUEST_TIMEOUT)
            if sqli_core.looks_like_sql_error(resp.text):
                _msgs.put(f"[POTENTIAL SQLi] {url}  (SQL error signature in response)")
        except requests.RequestException as e:
            _msgs.put(f"[error] {url}: {e}")


def start_testing():
    base_url = baseurl_entry.get().strip()
    if not base_url:
        messagebox.showerror("Input Error", "Please enter the Base URL.")
        return
    file_path = file_entry.get().strip()
    if not file_path:
        messagebox.showerror("Input Error", "Please load a valid OpenAPI file.")
        return

    spec = load_openapi_spec(file_path)
    if spec is None:
        return
    paths = sqli_core.extract_paths(spec)
    if not paths:
        messagebox.showerror("Error", "No paths found in the OpenAPI spec.")
        return

    payloads = sqli_core.DEFAULT_PAYLOADS
    total = sqli_core.total_requests(len(paths), len(payloads))
    host = urlparse(base_url).netloc or base_url
    if not messagebox.askokcancel(
        "Confirm SQLi test",
        f"Send {total} SQLi test requests to '{host}'\n"
        f"({len(paths)} endpoints x {len(payloads)} payloads).\n\n"
        f"Only test targets you are authorized to. Proceed?",
        icon="warning",
    ):
        return

    result_text.insert(tk.END, f"Testing {len(paths)} endpoints x {len(payloads)} "
                               f"payloads = {total} requests (<= {MAX_WORKERS} concurrent)...\n")
    result_text.see(tk.END)

    def run():
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            for path in paths:
                ex.submit(test_endpoint, base_url, path, payloads)
        _msgs.put("[done] Testing complete.")

    threading.Thread(target=run, daemon=True).start()


def drain_messages():
    """Main-thread pump: move worker messages into the text widget safely."""
    try:
        while True:
            result_text.insert(tk.END, _msgs.get_nowait() + "\n")
            result_text.see(tk.END)
    except queue.Empty:
        pass
    root.after(200, drain_messages)


def browse_file():
    file_path = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json")])
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)


# ---- GUI ----
root = tk.Tk()
root.title("API SQL Injection Tester")

tk.Label(root, text="Base URL:").pack(pady=5)
baseurl_entry = tk.Entry(root, width=80)
baseurl_entry.pack(pady=5)

tk.Label(root, text="OpenAPI File:").pack(pady=5)
file_entry = tk.Entry(root, width=80)
file_entry.pack(pady=5)

tk.Button(root, text="Browse", command=browse_file).pack(pady=5)
tk.Button(root, text="Start Testing", command=start_testing).pack(pady=20)

result_text = scrolledtext.ScrolledText(root, height=20, width=80)
result_text.pack(pady=5)

root.after(200, drain_messages)
root.mainloop()
