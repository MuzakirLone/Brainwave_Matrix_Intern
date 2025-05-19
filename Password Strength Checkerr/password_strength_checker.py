import sys
import re
import math
from PyQt5 import QtWidgets, QtGui, QtCore
import qdarkstyle
from PyQt5.QtWidgets import QGraphicsOpacityEffect

# ============================ Backend Logic ============================

def calculate_entropy(password: str) -> float:
    charset = 0
    if re.search(r'[a-z]', password):
        charset += 26
    if re.search(r'[A-Z]', password):
        charset += 26
    if re.search(r'\d', password):
        charset += 10
    if re.search(r'[\W_]', password):
        charset += 32
    return len(password) * math.log2(charset) if charset else 0


def evaluate_password(password: str):
    score = 0
    suggestions = []
    length = len(password)
    
    if length >= 12:
        score += 2
    elif length >= 8:
        score += 1
    else:
        suggestions.append("▶ Use at least 12 characters.")
    
    if re.search(r'[a-z]', password):
        score += 1
    else:
        suggestions.append("▶ Add lowercase letters.")
        
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        suggestions.append("▶ Add uppercase letters.")
        
    if re.search(r'\d', password):
        score += 1
    else:
        suggestions.append("▶ Add numbers.")
        
    if re.search(r'[\W_]', password):
        score += 1
    else:
        suggestions.append("▶ Add symbols (!@#$%).")
        
    if re.search(r'(.)\1{2,}', password):
        score -= 1
        suggestions.append("▶ Avoid repeating characters.")
        
    if password.lower() in {"password", "123456", "qwerty", "abc123", "letmein"}:
        score -= 2
        suggestions.append("▶ Avoid common passwords.")
        
    entropy = calculate_entropy(password)
    return score, entropy, suggestions


def strength_label(score: int, entropy: float):
    if score >= 7 and entropy >= 80:
        return "Very Strong", "#3498db"  # Blue
    if score >= 5 or entropy >= 60:
        return "Strong", "#2ecc71"       # Green
    if score >= 3:
        return "Moderate", "#e67e22"     # Orange
    return "Weak", "#e74c3c"             # Red

# ============================ Main Window ============================

class PasswordCheckerApp(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔒 Password Strength Checker")
        self.setFixedSize(500, 500)
        self.dark_mode = True  # Start in dark mode
        self._build_ui()
        self.show()

    def _build_ui(self):
        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(central)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        self.setCentralWidget(central)

        # Title
        title = QtWidgets.QLabel("Password Strength Checker", alignment=QtCore.Qt.AlignCenter)
        title.setFont(QtGui.QFont("Segoe UI", 18, QtGui.QFont.Bold))
        layout.addWidget(title)

        # Password input and buttons
        pw_layout = QtWidgets.QHBoxLayout()
        self.pw_edit = QtWidgets.QLineEdit()
        self.pw_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.pw_edit.setPlaceholderText("Enter password...")
        self.pw_edit.setFont(QtGui.QFont("Segoe UI", 14))
        self.pw_edit.textChanged.connect(self.on_text_changed)
        pw_layout.addWidget(self.pw_edit)

        self.toggle_btn = QtWidgets.QPushButton("Show")
        self.toggle_btn.setCheckable(True)
        self.toggle_btn.toggled.connect(self.on_toggle_password)
        pw_layout.addWidget(self.toggle_btn)

        self.copy_btn = QtWidgets.QPushButton("Copy")
        self.copy_btn.clicked.connect(self.copy_password)
        pw_layout.addWidget(self.copy_btn)

        layout.addLayout(pw_layout)

        # Copied label
        self.copy_status = QtWidgets.QLabel("Copied! 🎉")
        self.copy_status.setStyleSheet("color: #2ecc71; font-weight: bold;")
        self.copy_status.setVisible(False)
        self.opacity_effect = QGraphicsOpacityEffect(self.copy_status)
        self.copy_status.setGraphicsEffect(self.opacity_effect)
        layout.addWidget(self.copy_status)

        # Strength label
        self.strength_label = QtWidgets.QLabel("Strength: —")
        self.strength_label.setFont(QtGui.QFont("Segoe UI", 14))
        layout.addWidget(self.strength_label)

        # Progress bar
        self.progress_bar = QtWidgets.QProgressBar()
        self.progress_bar.setFixedHeight(20)
        self.progress_bar.setTextVisible(False)
        layout.addWidget(self.progress_bar)

        # Suggestions title
        suggestions_title = QtWidgets.QLabel("Suggestions:", font=QtGui.QFont("Segoe UI", 14, QtGui.QFont.Bold))
        layout.addWidget(suggestions_title)

        # Suggestions list
        self.suggestions_list = QtWidgets.QListWidget()
        self.suggestions_list.setFont(QtGui.QFont("Segoe UI", 11))
        layout.addWidget(self.suggestions_list, stretch=1)

        # Theme toggle button
        self.theme_btn = QtWidgets.QPushButton("Toggle Dark/Light Theme")
        self.theme_btn.clicked.connect(self.toggle_theme)
        layout.addWidget(self.theme_btn)

    def on_toggle_password(self, checked):
        if checked:
            self.pw_edit.setEchoMode(QtWidgets.QLineEdit.Normal)
            self.toggle_btn.setText("Hide")
        else:
            self.pw_edit.setEchoMode(QtWidgets.QLineEdit.Password)
            self.toggle_btn.setText("Show")

    def copy_password(self):
        password = self.pw_edit.text()
        if password:
            QtWidgets.QApplication.clipboard().setText(password)
            self.show_copied_message()

    def show_copied_message(self):
        self.copy_status.setVisible(True)
        animation = QtCore.QPropertyAnimation(self.opacity_effect, b"opacity")
        animation.setDuration(1500)
        animation.setStartValue(1.0)
        animation.setEndValue(0.0)
        animation.finished.connect(lambda: self.copy_status.setVisible(False))
        animation.start(QtCore.QAbstractAnimation.DeleteWhenStopped)

    def on_text_changed(self, text):
        if not text:
            self.reset_ui()
            return

        score, entropy, suggestions = evaluate_password(text)
        level, color = strength_label(score, entropy)

        self.strength_label.setText(f"Strength: {level}")
        self.strength_label.setStyleSheet(f"color: {color}")

        percent = {"Weak": 25, "Moderate": 50, "Strong": 75, "Very Strong": 100}[level]
        self.progress_bar.setValue(percent)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 5px;
            }}
            QProgressBar {{
                border: 1px solid #AAA;
                border-radius: 5px;
                background: #EEE;
            }}
        """)

        self.suggestions_list.clear()
        if suggestions:
            self.suggestions_list.addItems(suggestions)
        else:
            self.suggestions_list.addItem("👍 Great job! No suggestions.")

    def reset_ui(self):
        self.strength_label.setText("Strength: —")
        self.strength_label.setStyleSheet("")
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet("")
        self.suggestions_list.clear()

    def toggle_theme(self):
        if self.dark_mode:
            self.setStyleSheet("")  # Light mode
            self.dark_mode = False
        else:
            self.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())  # Dark mode
            self.dark_mode = True

# ============================ Entry Point ============================

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())  # Start with dark mode
    window = PasswordCheckerApp()
    sys.exit(app.exec_())
