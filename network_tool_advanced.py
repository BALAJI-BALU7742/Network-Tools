import sys
import socket
import requests
import whois
import dns.resolver
import speedtest
import subprocess
from io import BytesIO

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt6.QtGui import QFont, QIcon, QMovie, QPixmap
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QPushButton,
    QTextEdit, QLabel, QProgressBar, QFileDialog, QMessageBox, QDialog,
    QLineEdit, QFormLayout, QDialogButtonBox
)

# Helper: Download icon from URL and return QIcon
def icon_from_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        pixmap = QPixmap()
        pixmap.loadFromData(response.content)
        return QIcon(pixmap)
    except Exception as e:
        print(f"Failed to load icon from {url}: {e}")
        return QIcon()  # fallback empty icon

# Helper: Download gif from URL and return QMovie from bytes
def movie_from_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.content
        buffer = BytesIO(data)
        movie = QMovie()
        movie.loadFromData(buffer.read())
        return movie
    except Exception as e:
        print(f"Failed to load movie from {url}: {e}")
        return None

# Worker thread for running blocking tasks
class WorkerThread(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, func, *args):
        super().__init__()
        self.func = func
        self.args = args

    def run(self):
        try:
            result = self.func(*self.args)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))

# Custom input dialog for polished UX
class InputDialog(QDialog):
    def __init__(self, title, label, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setFixedSize(350, 120)

        layout = QVBoxLayout(self)

        form_layout = QFormLayout()
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText(label)
        form_layout.addRow(label, self.input_field)
        layout.addLayout(form_layout)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setStyleSheet("""
            QDialog {
                background-color: #ffffff;
            }
            QLabel {
                font-weight: 600;
                font-size: 13px;
            }
            QLineEdit {
                font-size: 14px;
                padding: 6px;
                border: 1.5px solid #aaa;
                border-radius: 6px;
            }
            QLineEdit:focus {
                border-color: #2e86de;
                outline: none;
            }
            QDialogButtonBox QPushButton {
                min-width: 70px;
                font-weight: 600;
                font-size: 13px;
                padding: 6px 10px;
                border-radius: 6px;
            }
            QDialogButtonBox QPushButton:hover {
                background-color: #d6e4ff;
            }
        """)

    def getText(self):
        return self.input_field.text().strip()

class NetworkTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Tool")
        self.resize(900, 700)
        self.logs = []

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QHBoxLayout(self.central_widget)

        self.sidebar = QWidget()
        self.sidebar.setFixedWidth(180)
        self.sidebar_layout = QVBoxLayout(self.sidebar)
        self.sidebar_layout.setContentsMargins(10, 10, 10, 10)
        self.sidebar_layout.setSpacing(15)

        icon_urls = {
            "globe": "https://www.freeiconspng.com/thumbs/globe-png/globe-png-hd-1.png",
            "location": "https://w7.pngwing.com/pngs/329/734/png-transparent-google-maps-location-zion-text-logo-sign-thumbnail.png",
            "speedometer": "https://sundayguardianlive.com/wp-content/uploads/2020/08/Dib-India-slow-internet-edited.jpeg",
            "dns": "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTBrjJUYMNmgoLWMY4kcbCsC4JUX-5g4nq3jw&s",
            "whois": "https://cdn.papaki.com/sites/all/themes/papaki3/n/whois/img/WHOIS_Share.png",
            "traceroute": "https://cdn.thenewstack.io/media/2025/04/861e0b4c-route-1024x552.png",
            "spinner_gif": "https://cdn.dribbble.com/userupload/20680844/file/original-a5a6bbdebdd0c283b9e2dae1408882bd.gif"
        }

        # Removed "Export Logs" button here:
        buttons_info = [
            ("Public IP", icon_urls["globe"], "Get your public IP address", self.public_ip),
            ("IP Geolocation", icon_urls["location"], "Find geographical info of your IP", self.ip_geolocation),
            ("Speed Test", icon_urls["speedometer"], "Test your internet download/upload speed", self.speed_test),
            ("DNS Lookup", icon_urls["dns"], "Query DNS records of a domain", self.dns_lookup),
            ("Whois Lookup", icon_urls["whois"], "Get Whois info for a domain/IP", self.whois_lookup),
            ("Traceroute", icon_urls["traceroute"], "Perform traceroute to a host", self.traceroute),
        ]

        self.buttons = []
        for text, icon_url, tooltip, method in buttons_info:
            btn = QPushButton(text)
            btn.setMinimumHeight(40)
            btn.setIcon(icon_from_url(icon_url))
            btn.setIconSize(QSize(24, 24))
            btn.setToolTip(tooltip)
            btn.clicked.connect(method)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #2e86de;
                    border-radius: 8px;
                    color: white;
                    font-weight: 600;
                    font-size: 14px;
                    padding-left: 12px;
                    text-align: left;
                }
                QPushButton:hover {
                    background-color: #1e6fb8;
                }
                QPushButton:pressed {
                    background-color: #144a75;
                }
            """)
            self.sidebar_layout.addWidget(btn)
            self.buttons.append(btn)

        self.sidebar_layout.addStretch()

        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)

        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setFont(QFont("Segoe UI", 10))
        self.output_area.setStyleSheet("""
            QTextEdit {
                background-color: white;
                border-radius: 8px;
                padding: 10px;
                border: 1px solid #d1d9e6;
            }
        """)
        self.content_layout.addWidget(self.output_area)

        self.status_label = QLabel("Ready")
        self.status_label.setFont(QFont("Segoe UI", 9))
        self.content_layout.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(15)
        self.progress_bar.setTextVisible(False)
        self.content_layout.addWidget(self.progress_bar)

        self.spinner_label = QLabel()
        self.spinner_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.spinner_label.setFixedSize(64, 64)
        self.content_layout.addWidget(self.spinner_label)
        self.spinner_label.hide()

        spinner_movie = movie_from_url(icon_urls["spinner_gif"])
        if spinner_movie:
            self.spinner_movie = spinner_movie
            self.spinner_label.setMovie(self.spinner_movie)
        else:
            self.spinner_movie = None

        self.main_layout.addWidget(self.sidebar)
        self.main_layout.addWidget(self.content_widget)

        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f7fa;
            }
            QLabel {
                color: #2f3640;
            }
            QProgressBar {
                border: 1px solid #d1d9e6;
                border-radius: 7px;
                background-color: #e4e9f2;
            }
            QProgressBar::chunk {
                background-color: #2e86de;
                border-radius: 7px;
            }
        """)

    # ---------- Button methods ----------

    def set_loading(self, loading=True):
        if loading:
            self.spinner_label.show()
            if self.spinner_movie:
                self.spinner_movie.start()
            self.progress_bar.setRange(0, 0)  # Indeterminate progress
            self.status_label.setText("Processing...")
            for b in self.buttons:
                b.setEnabled(False)
        else:
            self.spinner_label.hide()
            if self.spinner_movie:
                self.spinner_movie.stop()
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(100)
            self.status_label.setText("Ready")
            for b in self.buttons:
                b.setEnabled(True)

    def append_log(self, text):
        self.logs.append(text)
        self.output_area.append(text)

    def public_ip(self):
        self.output_area.clear()
        self.set_loading(True)

        def get_ip():
            resp = requests.get("https://api.ipify.org?format=text", timeout=10)
            return f"Your Public IP Address: {resp.text}"

        self.thread = WorkerThread(get_ip)
        self.thread.finished.connect(self._on_finished)
        self.thread.error.connect(self._on_error)
        self.thread.start()

    def ip_geolocation(self):
        self.output_area.clear()
        dlg = InputDialog("IP Geolocation", "Enter IP address or domain (leave empty for your IP)", self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            target = dlg.getText()
            if not target:
                # Use public IP
                try:
                    target = requests.get("https://api.ipify.org?format=text", timeout=10).text
                except Exception as e:
                    self.output_area.append(f"Failed to get public IP: {e}")
                    return
            self.set_loading(True)

            def geo_lookup(ip_or_domain):
                try:
                    resp = requests.get(f"https://ipinfo.io/{ip_or_domain}/json", timeout=10)
                    data = resp.json()
                    result = "IP Geolocation Result:\n"
                    for k, v in data.items():
                        result += f"{k}: {v}\n"
                    return result
                except Exception as e:
                    return f"Error during geolocation: {e}"

            self.thread = WorkerThread(geo_lookup, target)
            self.thread.finished.connect(self._on_finished)
            self.thread.error.connect(self._on_error)
            self.thread.start()

    def speed_test(self):
        self.output_area.clear()
        self.set_loading(True)

        def run_speedtest():
            st = speedtest.Speedtest()
            st.get_best_server()
            download = st.download() / 1_000_000  # Mbps
            upload = st.upload() / 1_000_000  # Mbps
            ping = st.results.ping
            return f"Speed Test Results:\nDownload Speed: {download:.2f} Mbps\nUpload Speed: {upload:.2f} Mbps\nPing: {ping:.2f} ms"

        self.thread = WorkerThread(run_speedtest)
        self.thread.finished.connect(self._on_finished)
        self.thread.error.connect(self._on_error)
        self.thread.start()

    def dns_lookup(self):
        self.output_area.clear()
        dlg = InputDialog("DNS Lookup", "Enter domain name", self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            domain = dlg.getText()
            if not domain:
                self.output_area.append("Domain cannot be empty.")
                return
            self.set_loading(True)

            def dns_query(domain_name):
                record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
                result = f"DNS Records for {domain_name}:\n"
                for rtype in record_types:
                    try:
                        answers = dns.resolver.resolve(domain_name, rtype, lifetime=5)
                        for rdata in answers:
                            result += f"{rtype}: {rdata.to_text()}\n"
                    except Exception:
                        result += f"{rtype}: No record found or query failed.\n"
                return result

            self.thread = WorkerThread(dns_query, domain)
            self.thread.finished.connect(self._on_finished)
            self.thread.error.connect(self._on_error)
            self.thread.start()

    def whois_lookup(self):
        self.output_area.clear()
        dlg = InputDialog("Whois Lookup", "Enter domain or IP", self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            query = dlg.getText()
            if not query:
                self.output_area.append("Input cannot be empty.")
                return
            self.set_loading(True)

            def whois_query(q):
                try:
                    w = whois.whois(q)
                    if isinstance(w, dict):
                        result = "Whois Info:\n"
                        for k, v in w.items():
                            result += f"{k}: {v}\n"
                    else:
                        result = str(w)
                    return result
                except Exception as e:
                    return f"Whois lookup failed: {e}"

            self.thread = WorkerThread(whois_query, query)
            self.thread.finished.connect(self._on_finished)
            self.thread.error.connect(self._on_error)
            self.thread.start()

    def traceroute(self):
        self.output_area.clear()
        dlg = InputDialog("Traceroute", "Enter host/domain to traceroute", self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            host = dlg.getText()
            if not host:
                self.output_area.append("Host cannot be empty.")
                return
            self.set_loading(True)

            def run_traceroute(hostname):
                try:
                    # Platform-dependent traceroute command
                    import platform
                    param = '-n' if platform.system().lower() == 'windows' else '-q 1'
                    command = []
                    if platform.system().lower() == 'windows':
                        command = ["tracert", "-d", hostname]
                    else:
                        command = ["traceroute", "-q", "1", hostname]

                    proc = subprocess.run(command, capture_output=True, text=True, timeout=30)
                    return proc.stdout
                except Exception as e:
                    return f"Traceroute failed: {e}"

            self.thread = WorkerThread(run_traceroute, host)
            self.thread.finished.connect(self._on_finished)
            self.thread.error.connect(self._on_error)
            self.thread.start()

    # Removed export_logs method

    # ---------- Thread signal handlers ----------

    def _on_finished(self, result):
        self.set_loading(False)
        self.append_log(result)

    def _on_error(self, err_msg):
        self.set_loading(False)
        self.append_log(f"Error: {err_msg}")

def main():
    app = QApplication(sys.argv)
    window = NetworkTool()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
