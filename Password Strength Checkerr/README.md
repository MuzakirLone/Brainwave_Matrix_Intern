
# 🔐 Password Strength Checker

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![PyQt5](https://img.shields.io/badge/Framework-PyQt5-green.svg)](https://pypi.org/project/PyQt5/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: PEP8](https://img.shields.io/badge/code%20style-PEP8-blue)](https://www.python.org/dev/peps/pep-0008/)
[![Build](https://github.com/MuzakirLone/password-strength-checker/actions/workflows/python-app.yml/badge.svg)](https://github.com/MuzakirLone/password-strength-checker/actions)



A modern GUI-based Password Strength Checker built using **Python** and **PyQt5**, designed to provide real-time password evaluation with entropy calculation, strength labeling, and improvement suggestions. This tool also includes dark/light theme toggling and clipboard copy functionality.

## 📌 Features

- **Real-time Password Evaluation** with:
  - Strength score
  - Entropy calculation
  - Color-coded feedback
  - Suggestions for improvement
- **Password Visibility Toggle**
- **Clipboard Copy Button**
- **Dark/Light Theme Toggle**
- **Smooth UI Animations**
- **Responsive & Intuitive Layout**

## 🖥️ GUI Preview

> _Add screenshots or screen recordings here showing the UI in action (optional)._

## ⚙️ How It Works

The password is evaluated using a scoring system based on:
- Length
- Use of lowercase, uppercase, numbers, and symbols
- Entropy (calculated using Shannon entropy principles)
- Avoidance of common passwords and repeated characters

The UI updates dynamically as the user types, giving immediate feedback and suggestions.

## 🧮 Password Evaluation Criteria

- **Length**
  - < 8: Weak
  - 8–11: Moderate
  - ≥ 12: Strong
- **Character Classes**
  - Lowercase, Uppercase, Digits, Symbols
- **Entropy Thresholds**
  - Very Strong: ≥ 80 bits
  - Strong: ≥ 60 bits
- **Bad Practices**
  - Common passwords
  - Repeating characters

## 🛠️ Requirements

- Python 3.x 
- PyQt5
- qdarkstyle

Install dependencies via pip:

```bash
pip install pyqt5 qdarkstyle
```

## 🚀 Getting Started

**Clone the repository:**
```
git clone https://github.com/yourusername/password-strength-checker.git
cd password-strength-checker
```

**Run the application:**
```
python main.py
```

**🧩 File Structure**
```
📁 password-strength-checker/
├── main.py            # Main application code
├── README.md          # Documentation
```
## 🌗 Themes

The application starts in **Dark Mode** (powered by `qdarkstyle`). You can toggle between **Dark/Light Mode** with a single click.

## 📋 License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/MuzakirLone/Brainwave_Matrix_Intern/blob/main/Password%20Strength%20Checkerr/LICENSE) file for details.

## 🙌 Acknowledgements

-   PyQt5 Documentation
    
-   [qdarkstyle](https://github.com/ColinDuquesnoy/QDarkStyleSheet) for dark UI themes
    
-   Entropy concept based on Shannon Information Theory
