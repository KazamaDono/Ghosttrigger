# gui.py (Complete Fixed Version)
"""
GhostTrigger Professional GUI
A sophisticated desktop application for authentication bypass detection.
"""

import sys
import asyncio
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QTableWidget, QTableWidgetItem,
    QTabWidget, QGroupBox, QFormLayout, QCheckBox, QComboBox, QSpinBox,
    QSplitter, QMessageBox, QProgressBar, QHeaderView, QFileDialog,
    QStatusBar, QToolBar, QFrame, QSizePolicy
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QSettings, QSize, QTimer
)
from PyQt6.QtGui import (
    QFont, QIcon, QPalette, QColor, QTextCursor, QAction, QFontDatabase
)

# Application modules
from config import TARGET_URL, USERNAME, PASSWORD, LOGIN_URL, LLM_BACKEND, OLLAMA_MODEL, REPORT_FILE
from crawler import WebCrawler
from analyzer import Analyzer
from exploiter import Exploiter
from reporter import Reporter


# ============================================================================
# WORKER THREAD
# ============================================================================

class ScanWorker(QThread):
    """Worker thread for running the scan without freezing the UI"""
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int, str)
    result_signal = pyqtSignal(dict)
    finished_signal = pyqtSignal()
    error_signal = pyqtSignal(str)

    def __init__(self, config: Dict[str, Any]):
        super().__init__()
        self.config = config
        self.results = None

    def log(self, message: str):
        self.log_signal.emit(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")

    def run(self):
        try:
            target_url = self.config.get('target_url', '')
            username = self.config.get('username', None) or None
            password = self.config.get('password', None) or None
            login_url = self.config.get('login_url', None) or None
            use_llm = self.config.get('use_llm', False)
            
            self.progress_signal.emit(10, "Initializing browser...")
            
            # Step 1: Crawl
            self.log(f"Starting scan on {target_url}")
            self.progress_signal.emit(20, "Crawling target website...")
            
            with WebCrawler(target_url, username, password, login_url) as crawler:
                page_data = crawler.run()
                self.log("Crawling completed successfully")
            
            # Step 2: Analyze
            self.progress_signal.emit(40, "Analyzing for vulnerabilities...")
            analyzer = Analyzer(page_data, use_llm=use_llm)
            candidates = asyncio.run(analyzer.run())
            self.log(f"Found {len(candidates)} potential vulnerability candidates")
            
            if not candidates:
                self.progress_signal.emit(100, "No vulnerabilities found")
                self.result_signal.emit({
                    'candidates': [],
                    'results': [],
                    'target_url': target_url
                })
                self.finished_signal.emit()
                return
            
            # Step 3: Exploit
            self.progress_signal.emit(60, "Attempting exploitation...")
            cookies = page_data.get("cookies") if page_data.get("cookies") else None
            with Exploiter(target_url, candidates, cookies) as exploiter:
                results = exploiter.run()
                self.log(f"Exploitation completed. {sum(1 for r in results if r.get('success'))} successful")
            
            # Step 4: Report generation
            self.progress_signal.emit(90, "Generating report...")
            
            self.result_signal.emit({
                'candidates': candidates,
                'results': results,
                'target_url': target_url,
                'page_data': page_data
            })
            
            self.progress_signal.emit(100, "Scan complete")
            self.finished_signal.emit()
            
        except Exception as e:
            self.error_signal.emit(str(e))
            self.log(f"ERROR: {str(e)}")


# ============================================================================
# LOG WIDGET
# ============================================================================

class LogWidget(QTextEdit):
    def __init__(self, max_lines: int = 1000):
        super().__init__()
        self.setReadOnly(True)
        # Use a safe default font
        font = QFont("Consolas", 9)
        if not font.exactMatch():
            font = QFont("Courier New", 9)
        self.setFont(font)
        self.max_lines = max_lines
        self.line_count = 0
        
    def append_log(self, message: str):
        self.append(message)
        self.line_count += 1
        
        # Trim old messages if we exceed max lines
        if self.line_count > self.max_lines:
            doc = self.document()
            cursor = QTextCursor(doc)
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            cursor.movePosition(QTextCursor.MoveOperation.Down, QTextCursor.MoveMode.KeepAnchor, 100)
            cursor.removeSelectedText()
            self.line_count -= 100
            
        # Auto-scroll to bottom
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.setTextCursor(cursor)


# ============================================================================
# RESULTS TABLE
# ============================================================================

class ResultsTable(QTableWidget):
    def __init__(self):
        super().__init__()
        self.setColumnCount(5)
        self.setHorizontalHeaderLabels(["Type", "Element ID", "Exploit", "Success", "Details"])
        self.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
    def populate(self, results: List[Dict[str, Any]]):
        self.setRowCount(len(results))
        for row, result in enumerate(results):
            candidate = result.get('candidate', {})
            cand_type = candidate.get('type', 'unknown')
            element_id = candidate.get('element_id', candidate.get('element_name', 'N/A'))
            exploit_js = candidate.get('exploit_js', '')
            if len(exploit_js) > 60:
                exploit_js = exploit_js[:60] + '...'
            success = "✅" if result.get('success') else "❌"
            error = result.get('error')
            
            # Handle None error properly
            if error is None:
                details = ""
            elif len(str(error)) > 50:
                details = str(error)[:50] + '...'
            else:
                details = str(error)
            
            self.setItem(row, 0, QTableWidgetItem(cand_type))
            self.setItem(row, 1, QTableWidgetItem(str(element_id)))
            self.setItem(row, 2, QTableWidgetItem(exploit_js))
            self.setItem(row, 3, QTableWidgetItem(success))
            self.setItem(row, 4, QTableWidgetItem(details))
            
            # Color code success/failure
            success_item = self.item(row, 3)
            if result.get('success'):
                success_item.setForeground(QColor(0, 150, 0))
            else:
                success_item.setForeground(QColor(200, 0, 0))


# ============================================================================
# DETAIL VIEW
# ============================================================================

class DetailView(QTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        # Use a safe default font
        font = QFont("Consolas", 9)
        if not font.exactMatch():
            font = QFont("Courier New", 9)
        self.setFont(font)
        
    def show_result(self, result: Dict[str, Any]):
        if not result:
            self.clear()
            return
            
        text = []
        candidate = result.get('candidate', {})
        
        text.append("=" * 70)
        text.append(f"CANDIDATE: {candidate.get('type', 'unknown').upper()}")
        text.append("=" * 70)
        text.append(f"Source: {candidate.get('source', 'N/A')}")
        text.append(f"Element ID: {candidate.get('element_id', candidate.get('element_name', 'N/A'))}")
        text.append(f"Success: {'YES' if result.get('success') else 'NO'}")
        
        if result.get('error'):
            text.append(f"Error: {result['error']}")
        
        text.append("")
        text.append("-" * 70)
        text.append("EXPLOIT CODE")
        text.append("-" * 70)
        text.append(candidate.get('exploit_js', '// No exploit generated'))
        
        if result.get('before'):
            text.append("")
            text.append("-" * 70)
            text.append("STATE BEFORE")
            text.append("-" * 70)
            text.append(f"URL: {result['before'].get('url', 'N/A')}")
            text.append(f"Cookies: {result['before'].get('cookies', [])}")
            text.append(f"Has Logout: {result['before'].get('has_logout', False)}")
            text.append(f"Has Welcome: {result['before'].get('has_welcome', False)}")
        
        if result.get('after'):
            text.append("")
            text.append("-" * 70)
            text.append("STATE AFTER")
            text.append("-" * 70)
            text.append(f"URL: {result['after'].get('url', 'N/A')}")
            text.append(f"Cookies: {result['after'].get('cookies', [])}")
            text.append(f"Has Logout: {result['after'].get('has_logout', False)}")
            text.append(f"Has Welcome: {result['after'].get('has_welcome', False)}")
        
        self.setText("\n".join(text))


# ============================================================================
# SETTINGS PANEL
# ============================================================================

class SettingsPanel(QWidget):
    settings_changed = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.settings = QSettings("GhostTrigger", "Professional")
        self.init_ui()
        self.load_settings()
        
    def init_ui(self):
        layout = QFormLayout()
        layout.setSpacing(15)
        
        # Target settings group
        target_group = QGroupBox("Target Configuration")
        target_layout = QFormLayout()
        
        self.target_url = QLineEdit()
        self.target_url.setPlaceholderText("http://localhost:5000")
        target_layout.addRow("Target URL:", self.target_url)
        
        self.login_url = QLineEdit()
        self.login_url.setPlaceholderText("Same as target URL if empty")
        target_layout.addRow("Login URL (optional):", self.login_url)
        
        self.username = QLineEdit()
        self.username.setPlaceholderText("Username for authentication")
        target_layout.addRow("Username:", self.username)
        
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("Password for authentication")
        target_layout.addRow("Password:", self.password)
        
        target_group.setLayout(target_layout)
        layout.addRow(target_group)
        
        # LLM settings group
        llm_group = QGroupBox("LLM Configuration")
        llm_layout = QFormLayout()
        
        self.use_llm = QCheckBox("Enable LLM-based filtering")
        self.use_llm.setToolTip("Use AI to filter false positives before exploitation")
        llm_layout.addRow(self.use_llm)
        
        self.llm_backend = QComboBox()
        self.llm_backend.addItems(["ollama", "openai"])
        llm_layout.addRow("Backend:", self.llm_backend)
        
        self.ollama_model = QLineEdit()
        self.ollama_model.setPlaceholderText("deepseek-coder, codellama, etc.")
        llm_layout.addRow("Ollama Model:", self.ollama_model)
        
        self.openai_api_key = QLineEdit()
        self.openai_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.openai_api_key.setPlaceholderText("sk-...")
        llm_layout.addRow("OpenAI API Key:", self.openai_api_key)
        
        self.openai_model = QComboBox()
        self.openai_model.addItems(["gpt-4", "gpt-3.5-turbo", "gpt-4-turbo-preview"])
        llm_layout.addRow("OpenAI Model:", self.openai_model)
        
        llm_group.setLayout(llm_layout)
        layout.addRow(llm_group)
        
        # Save button
        self.save_btn = QPushButton("Save Settings")
        self.save_btn.setFixedWidth(150)
        self.save_btn.clicked.connect(self.save_settings)
        layout.addRow("", self.save_btn)
        
        self.setLayout(layout)
        
    def load_settings(self):
        self.target_url.setText(self.settings.value("target_url", TARGET_URL))
        self.login_url.setText(self.settings.value("login_url", LOGIN_URL or ""))
        self.username.setText(self.settings.value("username", USERNAME or ""))
        self.password.setText(self.settings.value("password", PASSWORD or ""))
        self.use_llm.setChecked(self.settings.value("use_llm", False, type=bool))
        self.llm_backend.setCurrentText(self.settings.value("llm_backend", LLM_BACKEND))
        self.ollama_model.setText(self.settings.value("ollama_model", OLLAMA_MODEL))
        self.openai_api_key.setText(self.settings.value("openai_api_key", ""))
        self.openai_model.setCurrentText(self.settings.value("openai_model", "gpt-4"))
        
    def save_settings(self):
        self.settings.setValue("target_url", self.target_url.text())
        self.settings.setValue("login_url", self.login_url.text())
        self.settings.setValue("username", self.username.text())
        self.settings.setValue("password", self.password.text())
        self.settings.setValue("use_llm", self.use_llm.isChecked())
        self.settings.setValue("llm_backend", self.llm_backend.currentText())
        self.settings.setValue("ollama_model", self.ollama_model.text())
        self.settings.setValue("openai_api_key", self.openai_api_key.text())
        self.settings.setValue("openai_model", self.openai_model.currentText())
        
        QMessageBox.information(self, "Settings Saved", "Configuration saved successfully.")
        self.emit_settings()
        
    def emit_settings(self):
        config = {
            'target_url': self.target_url.text(),
            'login_url': self.login_url.text() or None,
            'username': self.username.text() or None,
            'password': self.password.text() or None,
            'use_llm': self.use_llm.isChecked(),
            'llm_backend': self.llm_backend.currentText(),
            'ollama_model': self.ollama_model.text(),
            'openai_api_key': self.openai_api_key.text(),
            'openai_model': self.openai_model.currentText(),
        }
        self.settings_changed.emit(config)


# ============================================================================
# MAIN WINDOW
# ============================================================================

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("GhostTrigger Professional - Authentication Bypass Detector")
        self.setMinimumSize(1200, 800)
        
        self.worker = None
        self.scan_results = None
        self.last_report = None
        
        self.setup_ui()
        self.setup_style()
        self.setup_connections()
        
    def setup_ui(self):
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(10)
        
        # Top toolbar
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(toolbar)
        
        # Action buttons
        self.start_action = QAction("▶ Start Scan", self)
        self.stop_action = QAction("■ Stop", self)
        self.stop_action.setEnabled(False)
        self.export_action = QAction("📄 Export Report", self)
        self.export_action.setEnabled(False)
        
        toolbar.addAction(self.start_action)
        toolbar.addAction(self.stop_action)
        toolbar.addSeparator()
        toolbar.addAction(self.export_action)
        
        # Spacer to push progress bar to the right
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        toolbar.addWidget(spacer)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(20)
        self.progress_bar.setFixedWidth(200)
        toolbar.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("Ready")
        self.status_label.setFixedWidth(200)
        toolbar.addWidget(self.status_label)
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)
        
        # Left panel: Settings and Results
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        # Tab widget
        self.tab_widget = QTabWidget()
        
        # Settings tab
        self.settings_panel = SettingsPanel()
        self.tab_widget.addTab(self.settings_panel, "⚙️ Configuration")
        
        # Results tab
        results_widget = QWidget()
        results_layout = QVBoxLayout(results_widget)
        self.results_table = ResultsTable()
        results_layout.addWidget(self.results_table)
        self.tab_widget.addTab(results_widget, "📊 Scan Results")
        
        left_layout.addWidget(self.tab_widget)
        
        # Right panel: Log and Detail
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        # Detail view
        detail_group = QGroupBox("Exploit Details")
        detail_layout = QVBoxLayout(detail_group)
        self.detail_view = DetailView()
        detail_layout.addWidget(self.detail_view)
        right_layout.addWidget(detail_group, 1)
        
        # Log view
        log_group = QGroupBox("Live Log")
        log_layout = QVBoxLayout(log_group)
        self.log_widget = LogWidget()
        log_layout.addWidget(self.log_widget)
        right_layout.addWidget(log_group, 1)
        
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([500, 700])
        
        # Status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("GhostTrigger Professional - Ready")
        
    def setup_style(self):
        # Professional dark theme with accent colors
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e2e;
            }
            QWidget {
                background-color: #1e1e2e;
                color: #cdd6f4;
                font-family: 'Segoe UI', 'Inter', 'Roboto', sans-serif;
                font-size: 12px;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #313244;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 10px;
                background-color: #181825;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 6px;
                color: #89b4fa;
            }
            QLineEdit, QComboBox, QTextEdit, QSpinBox {
                background-color: #11111b;
                border: 1px solid #313244;
                border-radius: 6px;
                padding: 6px 10px;
                selection-background-color: #89b4fa;
            }
            QLineEdit:focus, QComboBox:focus, QTextEdit:focus {
                border: 1px solid #89b4fa;
            }
            QPushButton {
                background-color: #313244;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45475a;
            }
            QPushButton:pressed {
                background-color: #1e1e2e;
            }
            QTableWidget {
                background-color: #11111b;
                alternate-background-color: #181825;
                gridline-color: #313244;
                border: none;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QHeaderView::section {
                background-color: #181825;
                padding: 8px;
                border: none;
                border-bottom: 1px solid #313244;
                font-weight: bold;
            }
            QTabWidget::pane {
                border: 1px solid #313244;
                border-radius: 8px;
                background-color: #181825;
            }
            QTabBar::tab {
                background-color: #11111b;
                padding: 8px 16px;
                margin-right: 4px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
            }
            QTabBar::tab:selected {
                background-color: #313244;
                color: #89b4fa;
            }
            QTabBar::tab:hover:!selected {
                background-color: #1e1e2e;
            }
            QProgressBar {
                border: 1px solid #313244;
                border-radius: 6px;
                text-align: center;
                background-color: #11111b;
            }
            QProgressBar::chunk {
                background-color: #89b4fa;
                border-radius: 5px;
            }
            QToolBar {
                background-color: #181825;
                border: none;
                border-bottom: 1px solid #313244;
                spacing: 8px;
                padding: 4px;
            }
            QCheckBox {
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                border-radius: 3px;
                border: 1px solid #313244;
                background-color: #11111b;
            }
            QCheckBox::indicator:checked {
                background-color: #89b4fa;
                border: 1px solid #89b4fa;
            }
            QScrollBar:vertical {
                background-color: #11111b;
                width: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background-color: #45475a;
                border-radius: 6px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #585b70;
            }
            QStatusBar {
                background-color: #181825;
                color: #a6adc8;
            }
        """)
        
    def setup_connections(self):
        self.start_action.triggered.connect(self.start_scan)
        self.stop_action.triggered.connect(self.stop_scan)
        self.export_action.triggered.connect(self.export_report)
        self.results_table.itemSelectionChanged.connect(self.on_result_selected)
        
    def start_scan(self):
        # Get configuration from settings
        config = {
            'target_url': self.settings_panel.target_url.text(),
            'login_url': self.settings_panel.login_url.text() or None,
            'username': self.settings_panel.username.text() or None,
            'password': self.settings_panel.password.text() or None,
            'use_llm': self.settings_panel.use_llm.isChecked(),
            'llm_backend': self.settings_panel.llm_backend.currentText(),
            'ollama_model': self.settings_panel.ollama_model.text(),
            'openai_api_key': self.settings_panel.openai_api_key.text(),
            'openai_model': self.settings_panel.openai_model.currentText(),
        }
        
        if not config['target_url']:
            QMessageBox.warning(self, "Missing Configuration", "Please enter a target URL.")
            return
        
        # Save settings
        self.settings_panel.save_settings()
        
        # Clear previous results
        self.results_table.setRowCount(0)
        self.detail_view.clear()
        self.log_widget.clear()
        self.progress_bar.setValue(0)
        self.status_label.setText("Scanning...")
        
        # Disable start button during scan
        self.start_action.setEnabled(False)
        self.stop_action.setEnabled(True)
        self.export_action.setEnabled(False)
        
        # Start worker thread
        self.worker = ScanWorker(config)
        self.worker.log_signal.connect(self.log_widget.append_log)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.result_signal.connect(self.on_scan_complete)
        self.worker.error_signal.connect(self.on_scan_error)
        self.worker.finished_signal.connect(self.on_worker_finished)
        
        self.worker.start()
        
    def stop_scan(self):
        if self.worker and self.worker.isRunning():
            self.worker.terminate()
            self.worker.wait()
            self.log_widget.append_log("[!] Scan stopped by user")
            self.status_label.setText("Stopped")
        self.stop_action.setEnabled(False)
        self.start_action.setEnabled(True)
        
    def update_progress(self, value: int, message: str):
        self.progress_bar.setValue(value)
        self.status_label.setText(message)
        
    def on_scan_complete(self, results: Dict[str, Any]):
        self.scan_results = results
        self.results_table.populate(results.get('results', []))
        
        # Generate report file
        reporter = Reporter(results['target_url'], results.get('results', []))
        report_path = f"ghosttrigger_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        reporter.save(report_path)
        self.last_report = report_path
        
        self.log_widget.append_log(f"[+] Report saved to {report_path}")
        
        # Summary
        total = len(results.get('results', []))
        successful = sum(1 for r in results.get('results', []) if r.get('success'))
        self.log_widget.append_log(f"[+] Scan complete: {successful}/{total} successful exploits")
        
        self.export_action.setEnabled(True)
        self.status_label.setText(f"Complete - {successful}/{total} successful")
        
    def on_scan_error(self, error: str):
        QMessageBox.critical(self, "Scan Error", f"An error occurred during the scan:\n\n{error}")
        self.log_widget.append_log(f"[ERROR] {error}")
        self.status_label.setText("Error")
        
    def on_worker_finished(self):
        self.start_action.setEnabled(True)
        self.stop_action.setEnabled(False)
        self.worker = None
        
    def on_result_selected(self):
        selected = self.results_table.currentRow()
        if selected >= 0 and self.scan_results:
            results = self.scan_results.get('results', [])
            if selected < len(results):
                self.detail_view.show_result(results[selected])
                
    def export_report(self):
        if hasattr(self, 'last_report') and self.last_report and Path(self.last_report).exists():
            # Ask user where to save
            path, _ = QFileDialog.getSaveFileName(
                self, "Export Report", 
                f"ghosttrigger_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                "Markdown Files (*.md);;All Files (*)"
            )
            if path:
                import shutil
                shutil.copy(self.last_report, path)
                QMessageBox.information(self, "Export Successful", f"Report exported to:\n{path}")
        else:
            QMessageBox.warning(self, "No Report", "No scan report available. Please run a scan first.")


# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("GhostTrigger Professional")
    app.setOrganizationName("GhostTrigger")
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()