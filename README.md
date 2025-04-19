# ⚡️ Phishing Scanner - Cybersecurity Edition

A modern, cyberpunk-themed desktop application for detecting phishing URLs using heuristic analysis, machine learning, and real-time SSL checks. Features a 3D animated scanning meter and a user-friendly interface for both single and batch URL scanning.

---

## Features

- **Heuristic Phishing Detection:** Scans URLs for suspicious patterns, keywords, and security issues.
- **Machine Learning Integration:** Optionally uses a pre-trained ML model (`phishing_model.pkl`) for advanced phishing detection.
- **SSL Certificate Validation:** Checks for valid SSL certificates to ensure secure connections.
- **3D Cyberpunk Progress Meter:** Animated OpenGL-based meter visualizes scanning progress in a futuristic style.
- **Batch URL Scanning:** Upload a `.txt` file of URLs for bulk analysis with progress tracking.
- **Scan History:** Automatically logs all scans with timestamps; view, clear, and export history.
- **Export Results:** Save batch scan results as a CSV file.
- **Modern UI:** Built with Tkinter and ttkbootstrap for a dark, cyberpunk look.

---

## Screenshots
![Screenshot 2025-04-20 003508](https://github.com/user-attachments/assets/a234cbf3-a5a8-4953-8d19-44492972eb4a)
![Screenshot 2025-04-20 003547](https://github.com/user-attachments/assets/4170e7a8-b956-439f-85d2-e146a3faa518)
![Screenshot 2025-04-20 003607](https://github.com/user-attachments/assets/b0da66fd-097c-4221-bb8a-37a137744337)
![Screenshot 2025-04-20 003618](https://github.com/user-attachments/assets/2990d16b-8665-433a-8e27-80b2c21d711e)
![Screenshot 2025-04-20 003646](https://github.com/user-attachments/assets/2f1a2f19-e34b-4290-9b9d-73b4882df8d9)
![Screenshot 2025-04-20 003659](https://github.com/user-attachments/assets/fbb4f436-fd87-4c89-95fd-a699343e89d1)

---

## Installation

### **Requirements**

- Python 3.8+
- The following Python packages:
  - `tkinter`
  - `ttkbootstrap`
  - `requests`
  - `tldextract`
  - `joblib`
  - `os`, `json`, `datetime`, `re`, `ssl`, `socket`, `threading`, `queue`, `concurrent.futures`, `csv` (built-in)
  - `pyopengltk`
  - `PyOpenGL`
  - `scikit-learn` (for model loading)
- Fonts: `Fira Mono`, `Orbitron` (for best UI appearance)

_Install dependencies with:_

```
pip install ttkbootstrap requests tldextract joblib pyopengltk PyOpenGL scikit-learn
```
> _Note: On some systems, you may need to install `tkinter` and OpenGL libraries separately._

---

## Usage

1. **Run the Application:**
```
python Phishing_Scanner.py
```

2. **Single URL Scan:**
- Enter a URL in the input field.
- Click **Scan URL**.
- View results and analysis in the output area.

3. **Batch Scan:**
- Click **Upload URLs** and select a `.txt` file with one URL per line.
- The app will process all URLs and display results.

4. **Export Results:**
- After batch scanning, click **Export Results** to save a CSV file.

5. **View and Manage History:**
- Click **View History** to see all past scans.
- Optionally clear history from the history window.

---

## Data Details

### **Heuristic Analysis**

- **Checks for:**
- Suspicious keywords (e.g., `login`, `verify`, `secure`, `account`, `update`, `bank`, `free`, `offer`, `password`, `confirm`)
- Use of IP addresses instead of domains
- Excessive subdomain levels
- Hyphens in the domain
- Use of HTTPS and SSL certificate validity
- Website accessibility and HTTP status codes

### **Extracted Features for ML Model**

| Feature Name        | Description                                    |
|---------------------|------------------------------------------------|
| url_length          | Length of the URL                              |
| num_dots            | Number of dots in the URL                      |
| num_hyphens         | Number of hyphens in the hostname              |
| num_at              | Number of '@' characters in the URL            |
| num_percent         | Number of '%' characters in the URL            |
| num_queries         | Number of query parameters                     |
| num_ampersands      | Number of '&' characters in the URL            |
| num_digits          | Number of digits in the URL                    |
| https_token         | 'https' present in hostname (1/0)              |
| has_ip              | Hostname is an IP address (1/0)                |
| has_at              | '@' present in URL (1/0)                       |
| uses_https          | URL uses HTTPS scheme (1/0)                    |
| subdomain_level     | Number of subdomain levels                     |
| path_length         | Length of the URL path                         |
| hostname_length     | Length of the hostname                         |
| suspicious_words    | Count of suspicious words in the URL           |

### **Scan History**

- Stored in `scan_history.json`
- Each scan record:
- `url`: The scanned URL
- `timestamp`: Date and time of scan
- `result`: Heuristic result summary
- `details`: List of specific warnings or checks (for batch scans)

### **Batch Results Export**

- CSV file columns:
- `URL`
- `Timestamp`
- `Result`
- `Details` (semicolon-separated list)

---

## File Structure

```
Phishing_Scanner.py
phishing_model.pkl # (Optional) Pre-trained ML model
scan_history.json # (Auto-generated) Scan history log
requirements.txt # (Recommended) List of dependencies
```

---

## How it Works

- **GUI:** Built with Tkinter and ttkbootstrap for a modern look.
- **3D Meter:** Uses PyOpenGL and pyopengltk for animated progress visualization.
- **Heuristics:** Uses regex, URL parsing, and HTTP/SSL checks.
- **ML Model:** If `phishing_model.pkl` is present, uses scikit-learn to predict phishing likelihood.
- **Threading:** Uses threads and thread-safe UI updates for smooth operation during scans.

---

## Limitations

- ML prediction requires a compatible `phishing_model.pkl` file.
- SSL checks require internet access and may fail for unreachable domains.
- Batch scans are limited by system resources and network speed.

---

## Credits

- Inspired by modern cybersecurity tools and cyberpunk aesthetics.
- Uses open-source libraries: Tkinter, ttkbootstrap, PyOpenGL, pyopengltk, scikit-learn, tldextract, requests.

---

## Contributing

Pull requests and suggestions welcome! Please open an issue for bugs or feature requests.

---

## Author

_MuzakirLone / GitHub handle_

---

> _For any issues, please contact via GitHub Issues_





