
# 🔐 Password Strength Checker

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![PyQt5](https://img.shields.io/badge/Framework-PyQt5-green.svg)](https://pypi.org/project/PyQt5/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: PEP8](https://img.shields.io/badge/code%20style-PEP8-blue)](https://www.python.org/dev/peps/pep-0008/)


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

![Screenshot 2025-05-19 185543](https://github.com/user-attachments/assets/1f0957fc-e973-4088-a7c0-be489cacb1c1)
![Screenshot 2025-05-19 185550](https://github.com/user-attachments/assets/5f5903ec-2c7e-4330-9ae2-07b436535eec)
![Screenshot 2025-05-19 185557](https://github.com/user-attachments/assets/9e989aea-735e-48f8-9fe5-714dd9b34ebc)
![Screenshot 2025-05-19 185608](https://github.com/user-attachments/assets/e224f407-5eb7-4167-b558-e448ae620620)
![Screenshot 2025-05-19 185625](https://github.com/user-attachments/assets/5489397f-9db2-417d-a9e4-51cdd8df8220)
![Screenshot 2025-05-19 185638](https://github.com/user-attachments/assets/bfd4c7c9-1abb-4e8f-a7dc-15983d9d43ba)

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
git clone --no-checkout https://github.com/MuzakirLone/Brainwave_Matrix_Intern.git
cd Brainwave_Matrix_Intern
git sparse-checkout init
git sparse-checkout set "Password Strength Checker"
git checkout
cd "Password Strength Checker"
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
