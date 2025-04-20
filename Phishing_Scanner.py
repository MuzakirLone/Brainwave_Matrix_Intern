import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import re
import requests
from urllib.parse import urlparse
import joblib
import os
import json
from datetime import datetime
import tldextract
import ssl
import socket
from threading import Thread
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
import csv
from pyopengltk import OpenGLFrame
from OpenGL.GL import *
from OpenGL.GLU import *
import ttkbootstrap as tb
from ttkbootstrap.widgets import Meter
import math

class GLScannerMeter(OpenGLFrame):
    """3D Scanning Progress Meter with Cyberpunk Style"""
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.rotation = 0
        self.scan_progress = 0
        self.pulse_effect = 0
        self.pulse_direction = 1
        # Add neon border for better visibility
        self.configure(bg="#181c26", highlightbackground="#39ff14", highlightthickness=2)
        # Make sure initgl is called after widget is created
        self.bind('<Map>', lambda _: self.after(100, self.initgl))

    def initgl(self):
        # Make sure the widget is visible before initializing OpenGL
        if not self.winfo_ismapped():
            return
            
        glEnable(GL_DEPTH_TEST)
        glEnable(GL_BLEND)  # Enable blending for transparency
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA)
        glEnable(GL_LIGHTING)
        glEnable(GL_LIGHT0)
        glLightfv(GL_LIGHT0, GL_POSITION, (0.0, 0.0, 1.0, 0.0))
        glLightfv(GL_LIGHT0, GL_AMBIENT, (0.2, 0.2, 0.2, 1.0))
        glLightfv(GL_LIGHT0, GL_DIFFUSE, (0.8, 0.8, 0.8, 1.0))
        glEnable(GL_LIGHTING)
        glEnable(GL_LIGHT0)
        glLightfv(GL_LIGHT0, GL_POSITION, (0.0, 0.0, 1.0, 0.0))
        glLightfv(GL_LIGHT0, GL_AMBIENT, (0.2, 0.2, 0.2, 1.0))
        glLightfv(GL_LIGHT0, GL_DIFFUSE, (0.8, 0.8, 0.8, 1.0))
        glMatrixMode(GL_PROJECTION)
        glLoadIdentity()
        gluPerspective(45, (self.width/self.height), 0.1, 50.0)
        glMatrixMode(GL_MODELVIEW)
        glLoadIdentity()
        glTranslatef(0.0, 0.0, -5)
        glClearColor(0.0, 0.0, 0.0, 1.0)
        glClearColor(0.0, 0.0, 0.0, 1.0)
        
        # Start the redraw loop
        self.after(20, self.redraw)

    def redraw(self):
        if not self.winfo_ismapped():
            self.after(100, self.redraw)
            return
            
        # Update pulse effect for cyberpunk glow
        self.pulse_effect += 0.05 * self.pulse_direction
        if self.pulse_effect > 1.0:
            self.pulse_effect = 1.0
            self.pulse_direction = -1
        elif self.pulse_effect < 0.3:
            self.pulse_effect = 0.3
            self.pulse_direction = 1
            
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT)
        glLoadIdentity()
        
        # Cyberpunk-style scanning ring
        glTranslatef(0, 0, -5)
        glRotatef(self.rotation, 0, 1, 0)
        glRotatef(30, 1, 0, 0)  # Tilt for 3D effect
        self.rotation = (self.rotation + 2) % 360
        
        # Background glow
        glBegin(GL_TRIANGLE_FAN)
        glColor4f(0.0, 0.2, 0.1, 0.2)  # Dark green glow
        glVertex3f(0, 0, 0)
        for i in range(0, 361, 10):
            glVertex3f(1.8 * math.cos(math.radians(i)), 1.8 * math.sin(math.radians(i)), 0)
        glEnd()
        
        # Outer ring with pulse effect
        glBegin(GL_LINE_LOOP)
        glColor3f(0.0, 1.0 * self.pulse_effect, 0.2)  # Pulsing neon green
        for i in range(0, 360, 5):
            glVertex3f(1.5 * math.cos(math.radians(i)), 1.5 * math.sin(math.radians(i)), 0)
        glEnd()
        
        # Inner ring
        glBegin(GL_LINE_LOOP)
        glColor3f(0.0, 0.7, 0.9)  # Cyan
        for i in range(0, 360, 10):
            glVertex3f(1.2 * math.cos(math.radians(i)), 1.2 * math.sin(math.radians(i)), 0)
        glEnd()
        
        # Progress fill
        glBegin(GL_TRIANGLE_FAN)
        glColor4f(0.2, 1.0, 0.3, 0.5)  # Semi-transparent fill
        glVertex3f(0, 0, 0)
        for i in range(0, int(3.6 * self.scan_progress) + 1):
            angle = math.radians(i)
            glVertex3f(math.cos(angle), math.sin(angle), 0)
        glEnd()
        
        # Scanning line effect
        if self.scan_progress > 0:
            glBegin(GL_LINES)
            glColor3f(1.0, 1.0, 0.3)  # Yellow scanning line
            scan_angle = math.radians(3.6 * self.scan_progress)
            glVertex3f(0, 0, 0)
            glVertex3f(1.5 * math.cos(scan_angle), 1.5 * math.sin(scan_angle), 0)
            glEnd()
        
        self.tkSwapBuffers()
        self.after(20, self.redraw)

    def set_progress(self, value):
        self.scan_progress = value

class PhishingScanner:
    def __init__(self):
        self.model = self.load_model()
        self.history = self.load_history()
        self.url_queue = Queue()
        self.batch_results = []
        self.setup_gui()

    def load_model(self):
        MODEL_PATH = "phishing_model.pkl"
        if os.path.exists(MODEL_PATH):
            return joblib.load(MODEL_PATH)
        print("⚠️ Model file not found. ML prediction will not work.")
        return None

    def load_history(self):
        history_file = "scan_history.json"
        if os.path.exists(history_file):
            with open(history_file, 'r') as f:
                return json.load(f)
        return []

    def save_history(self):
        with open("scan_history.json", 'w') as f:
            json.dump(self.history, f)

    def extract_features(self, url):
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        ext = tldextract.extract(url)
        path = parsed.path or ""
        query = parsed.query or ""

        features = {
            'url_length': len(url),
            'num_dots': url.count('.'),
            'num_hyphens': hostname.count('-'),
            'num_at': url.count('@'),
            'num_percent': url.count('%'),
            'num_queries': len(query.split('&')),
            'num_ampersands': url.count('&'),
            'num_digits': sum(c.isdigit() for c in url),
            'https_token': 1 if 'https' in hostname else 0,
            'has_ip': 1 if re.match(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', hostname) else 0,
            'has_at': 1 if '@' in url else 0,
            'uses_https': 1 if parsed.scheme == "https" else 0,
            'subdomain_level': len(ext.subdomain.split('.')) if ext.subdomain else 0,
            'path_length': len(path),
            'hostname_length': len(hostname),
            'suspicious_words': sum(1 for word in ['login', 'signin', 'verify', 'secure', 'account', 'update', 'bank', 'free', 'offer', 'password'] if word in url.lower())
        }
        return list(features.values())

    def check_ssl_cert(self, url):
        try:
            hostname = urlparse(url).netloc
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return "✅ Valid SSL Certificate", True
        except Exception as e:
            return f"⚠️ SSL Certificate Issue: {str(e)}", False

    def is_suspicious(self, url):
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return "❌ Invalid URL", []

        hostname = parsed.hostname or ""
        warnings = []
        checks = []

        suspicious_keywords = ["login", "verify", "secure", "account", "update", "bank", "free", "offer", "password", "confirm"]
        if any(keyword in url.lower() for keyword in suspicious_keywords):
            warnings.append("Contains suspicious keyword(s)")

        ip_address_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        if re.match(ip_address_pattern, hostname):
            warnings.append("Uses IP address instead of domain")

        ext = tldextract.extract(url)
        if len(ext.subdomain.split('.')) > 2:
            warnings.append("Excessive subdomain levels")

        if '-' in hostname:
            warnings.append("Contains hyphens (often used in phishing)")

        if not url.startswith("https://"):
            warnings.append("Does not use HTTPS")
        else:
            ssl_result, is_valid = self.check_ssl_cert(url)
            checks.append(ssl_result)

        try:
            response = requests.get(url, timeout=5, verify=True)
            if response.status_code >= 400:
                warnings.append(f"Website error: {response.status_code}")
            checks.append("✅ Website accessible")
        except Exception as e:
            warnings.append(f"Website not reachable: {str(e)}")

        result = "✅ Heuristically looks safe." if not warnings else "⚠️ Potential phishing detected"
        return result, warnings + checks

    def scan_url(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL")
            return

        self.result_text.config(state='normal')
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, "🔍 Scanning URL...\n")
        self.result_text.insert(tk.END, "\n[SYSTEM] Initializing scan protocols...\n")
        self.result_text.config(state='disabled')

        self.scan_button.config(state='disabled')
        self.meter.set_progress(0)
        self.meter.pack(pady=10)
        self.root.update()

        def scan_thread():
            try:
                # Smoother progress animation with thread-safe updates
                for i in range(1, 101, 1):
                    # Thread-safe UI update using after method
                    progress = i/100
                    self.root.after(0, lambda p=progress: self.meter.set_progress(p))
                    
                    # Add cyberpunk-style progress messages at certain points
                    if i == 25:
                        self.root.after(0, lambda: self.update_scan_status("[SYSTEM] Analyzing URL structure..."))
                    elif i == 50:
                        self.root.after(0, lambda: self.update_scan_status("[SYSTEM] Checking security certificates..."))
                    elif i == 75:
                        self.root.after(0, lambda: self.update_scan_status("[SYSTEM] Running heuristic analysis..."))
                    
                    time.sleep(0.05)
                
                heuristic_result, details = self.is_suspicious(url)
                self.root.after(0, lambda: self.update_results(url, heuristic_result, details))
                self.root.after(0, lambda: self.meter.pack_forget())
            except Exception as e:
                # Handle any exceptions in the thread
                self.root.after(0, lambda: self.handle_scan_error(str(e)))

        Thread(target=scan_thread).start()
        
    def update_scan_status(self, message):
        """Thread-safe method to update scan status"""
        self.result_text.config(state='normal')
        self.result_text.insert(tk.END, f"\n{message}\n")
        self.result_text.see(tk.END)  # Auto-scroll to the end
        self.result_text.config(state='disabled')
        
    def handle_scan_error(self, error_message):
        """Handle errors that occur during scanning"""
        self.result_text.config(state='normal')
        self.result_text.insert(tk.END, f"\n⚠️ Error during scan: {error_message}\n")
        self.result_text.config(state='disabled')
        self.scan_button.config(state='normal')
        self.meter.pack_forget()

    def update_results(self, url, heuristic_result, details):
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"URL: {url}\n\n{heuristic_result}\n\n")
        
        if details:
            self.result_text.insert(tk.END, "Detailed Analysis:\n")
            for detail in details:
                self.result_text.insert(tk.END, f"• {detail}\n")

        if self.model:
            try:
                features = self.extract_features(url)
                prediction = self.model.predict([features])[0]
                ml_result = "⚠️ ML Prediction: Likely Phishing" if prediction == 1 else "✅ ML Prediction: Likely Safe"
                self.result_text.insert(tk.END, f"\n{ml_result}")
            except Exception as e:
                self.result_text.insert(tk.END, f"\nML Analysis failed: {e}")

        scan_record = {
            "url": url,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "result": heuristic_result
        }
        self.history.append(scan_record)
        self.save_history()

        self.scan_button.config(state='normal')
        self.result_text.config(state='disabled')

    def setup_gui(self):
        self.root = tb.Window(themename="cyborg")
        self.root.title("\u26a1\ufe0f Phishing Scanner - Cybersecurity Edition")
        self.root.geometry("800x600")
        self.root.configure(bg="#10131a")
        
        # Import time module for animations
        import time
        
        # Create a splash effect with animation
        splash_frame = tk.Frame(self.root, bg="#10131a")
        splash_frame.pack(expand=True, fill=tk.BOTH)
        
        splash = tk.Label(splash_frame, text="INITIALIZING SECURITY SCANNER",
                          font=("Orbitron", 20, "bold"), bg="#10131a", fg="#39ff14")
        splash.pack(expand=True, pady=20)
        
        progress_text = tk.Label(splash_frame, text="Loading cybersecurity modules...",
                               font=("Fira Mono", 10), bg="#10131a", fg="#00ffe7")
        progress_text.pack(pady=10)
        
        self.root.update()
        time.sleep(1.5)
        progress_text.config(text="Calibrating neural networks...")
        self.root.update()
        time.sleep(1.5)
        progress_text.config(text="Establishing secure connection...")
        self.root.update()
        time.sleep(1.5)
        splash_frame.destroy()

        title = tk.Label(self.root, text="\u26a1\ufe0f Phishing Scanner",
                        font=("Orbitron", 32, "bold"), bg="#10131a", fg="#39ff14",
                        highlightbackground="#39ff14", highlightcolor="#39ff14", highlightthickness=2)
        title.pack(pady=18)

        input_frame = tk.Frame(self.root, bg="#10131a")
        input_frame.pack(fill=tk.X, padx=22)

        url_label = tk.Label(input_frame, text="Enter URL to scan:",
                            bg="#10131a", fg="#00ffe7", font=("Consolas", 13, "bold"))
        url_label.pack()

        self.url_entry = tb.Entry(input_frame, width=55, font=("Consolas", 13), bootstyle="dark")
        self.url_entry.pack(pady=6, ipady=6)

        button_frame = tk.Frame(self.root, bg="#10131a")
        button_frame.pack(pady=12)

        self.scan_button = tb.Button(button_frame, text="🔨 Scan URL", command=self.scan_url,
                                    bootstyle="success-outline", width=18)
        self.scan_button.pack(side=tk.LEFT, padx=6)

        upload_button = tb.Button(button_frame, text="📂 Upload URLs", command=self.upload_urls,
                                 bootstyle="info-outline", width=18)
        upload_button.pack(side=tk.LEFT, padx=6)

        history_button = tb.Button(button_frame, text="🗓 View History", command=self.show_history,
                                  bootstyle="primary-outline", width=18)
        history_button.pack(side=tk.LEFT, padx=6)

        export_button = tb.Button(button_frame, text="📄 Export Results", command=self.export_results,
                                 bootstyle="danger-outline", width=18)
        export_button.pack(side=tk.LEFT, padx=6)

        self.meter = GLScannerMeter(self.root, width=200, height=200)
        self.meter.pack_forget()

        self.result_text = scrolledtext.ScrolledText(self.root, height=15, width=80, wrap=tk.WORD,
                                                    bg="#181c26", fg="#39ff14", insertbackground="#39ff14",
                                                    font=("Fira Mono", 11, "bold"), borderwidth=0, relief=tk.FLAT)
        self.result_text.pack(pady=22, padx=22, fill=tk.BOTH, expand=True)
        self.result_text.config(state='disabled')

    def upload_urls(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if not file_path:
            return

        try:
            with open(file_path, 'r') as file:
                urls = [line.strip() for line in file if line.strip()]

            if not urls:
                messagebox.showwarning("Error", "No URLs found in the file")
                return

            self.batch_results = []
            self.result_text.config(state='normal')
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"🔍 Processing {len(urls)} URLs...\n\n")
            self.result_text.config(state='disabled')
            self.scan_button.config(state='disabled')

            Thread(target=self.process_batch_urls, args=(urls,)).start()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {str(e)}")

    def process_batch_urls(self, urls):
        # Reset progress meter for batch processing
        self.meter.set_progress(0)
        self.meter.pack(pady=10)
        self.root.update()
        
        # Update UI to show batch processing has started
        self.result_text.config(state='normal')
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"🔍 Processing {len(urls)} URLs...\n\n")
        self.result_text.insert(tk.END, "[SYSTEM] Initializing batch scan...\n")
        self.result_text.config(state='disabled')
        
        # Track progress for the meter
        total_urls = len(urls)
        processed = 0
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(self.is_suspicious, url) for url in urls]
            for url, future in zip(urls, futures):
                try:
                    # Update progress meter
                    processed += 1
                    progress = processed / total_urls
                    self.root.after(0, lambda p=progress: self.meter.set_progress(p))
                    
                    # Update status message periodically
                    if processed % max(1, total_urls // 10) == 0 or processed == total_urls:
                        self.root.after(0, lambda u=url, p=processed: self.update_scan_status(
                            f"[SYSTEM] Processing URL {p}/{total_urls}: {u[:30]}..."))
                    
                    result, details = future.result()
                    scan_record = {
                        "url": url,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "result": result,
                        "details": details
                    }
                    self.batch_results.append(scan_record)
                    self.history.append(scan_record)
                    
                    # Update results less frequently to avoid UI freezing
                    if processed % max(5, total_urls // 5) == 0 or processed == total_urls:
                        self.root.after(0, self.update_batch_results)
                        
                except Exception as e:
                    scan_record = {
                        "url": url,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "result": f"Error: {str(e)}",
                        "details": []
                    }
                    self.batch_results.append(scan_record)

        self.root.after(0, self.finalize_batch_scan)
        self.save_history()

    def update_batch_results(self):
        self.result_text.config(state='normal')
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Processed {len(self.batch_results)} URLs\n\n")
        
        for record in self.batch_results:
            self.result_text.insert(tk.END, f"URL: {record['url']}\nResult: {record['result']}\n")
            if record['details']:
                self.result_text.insert(tk.END, "Details:\n")
                for detail in record['details']:
                    self.result_text.insert(tk.END, f"• {detail}\n")
            self.result_text.insert(tk.END, "\n")

        self.result_text.config(state='disabled')

    def finalize_batch_scan(self):
        self.scan_button.config(state='normal')
        messagebox.showinfo("Complete", f"Finished scanning {len(self.batch_results)} URLs")

    def export_results(self):
        if not self.batch_results:
            messagebox.showwarning("Warning", "No batch results to export")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                filetypes=[("CSV Files", "*.csv")])
        if not file_path:
            return

        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow(["URL", "Timestamp", "Result", "Details"])
                for record in self.batch_results:
                    writer.writerow([
                        record['url'],
                        record['timestamp'],
                        record['result'],
                        '; '.join(record.get('details', []))
                    ])
            messagebox.showinfo("Success", "Results exported successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export results: {str(e)}")

    def show_history(self):
        history_window = tk.Toplevel(self.root)
        history_window.title("Scan History")
        history_window.geometry("600x400")
        history_window.configure(bg="#1e1e2f")

        button_frame = tk.Frame(history_window, bg="#1e1e2f")
        button_frame.pack(pady=5)

        clear_button = tb.Button(button_frame, text="Clear History", 
                                command=lambda: self.clear_and_update_history(history_window),
                                bootstyle="danger-outline")
        clear_button.pack()

        history_text = scrolledtext.ScrolledText(history_window, wrap=tk.WORD, width=70, height=20,
                                                bg="#2b2b3d", fg="#ffffff", font=("Fira Mono", 10))
        history_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        for scan in reversed(self.history):
            history_text.insert(tk.END, f"URL: {scan['url']}\n")
            history_text.insert(tk.END, f"Time: {scan['timestamp']}\n")
            history_text.insert(tk.END, f"Result: {scan['result']}\n\n")

        history_text.config(state='disabled')

    def clear_and_update_history(self, history_window):
        if self.clear_history():
            history_window.destroy()
            self.show_history()

    def clear_history(self):
        if messagebox.askyesno("Clear History", "Are you sure you want to clear all scan history?"):
            self.history = []
            self.batch_results = []
            self.save_history()
            
            # Update main screen to reflect cleared history
            self.result_text.config(state='normal')
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "History has been cleared.\n")
            self.result_text.config(state='disabled')
            
            messagebox.showinfo("Success", "History cleared successfully")
            return True
        return False

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = PhishingScanner()
    app.run()
