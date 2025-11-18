#!/usr/bin/env python3
import sys
import os
import subprocess
import re
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem
)
from PyQt5.QtCore import Qt
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEnginePage
from PyQt5.QtCore import QUrl

# pip install PyQtWebEngine
# pip libs may conflict on linux. untested on windows, but I think this is limited to system libs
# sudo apt-get install python3-pyqt5 python3-pyqt5.qtwebengine

# Silence Qt warnings
#os.environ["QT_LOGGING_RULES"] = "*.warning=false"  
os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = "--disable-logging --log-level=3"
#os.environ["QTWEBENGINE_DISABLE_SANDBOX"] = "1"



# CONFIG: OPTO MAC prefixes to match # will populate further later
MAC_PREFIXES = [
    "00:a0:3d",
    "6c:bf:b5",
    "b8:27:eb",
]

MAC_PREFIXES = [p.lower() for p in MAC_PREFIXES]



# Utilities
def scan_network():
    '''
    Ping sweep + ARP table parsing.
    Assumes a /24 like 192.168.1.x 
    '''
    print("Pinging network...")
    for i in range(1, 255):
        subprocess.Popen(
            ["ping", "-c", "1", "-W", "50", f"192.168.1.{i}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    print("Reading ARP table...")
    out = subprocess.check_output(["arp", "-n"]).decode()
                                  
    mac_re = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+.*\s+([0-9a-fA-F:]{17})")
                                               
    entries = []
    for ip, mac in mac_re.findall(out):
        entries.append((ip, mac.lower()))
                                                                                    
    return entries
                                                  
                                                               
def generate_hostname(mac):
    # Convert aa:bb:cc:dd:ee:ff -> opto-dd-ee-ff
    parts = mac.split(":")
    last3 = parts[-3:]
    return f"opto-{last3[0]}-{last3[1]}-{last3[2]}"
                                                               
                                                            
def is_link_local(ip):
    """Returns True if the IP is 169.254.x.x"""
    return ip.startswith("169.254.")

class InsecureWebPage(QWebEnginePage):
    def certificateError(self, error):
        # Accept all SSL certificates (self-signed, invalid, etc.)
        error.ignoreCertificateError()
        return True
                   
                                                                   
# GUI Application
class OptoScanner(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Opto Finder")
        self.resize(1400, 800)
                                           
        # insecurites
        self.browser = QWebEngineView()
        self.browser.setPage(InsecureWebPage(self.browser))

                                    
        # Layouts
        layout = QHBoxLayout()
        left = QVBoxLayout()
                                 
        # Scan button
        self.scan_button = QPushButton("Scan Network")
        self.scan_button.clicked.connect(self.do_scan)
                                               
        # Table with Hostname, MAC, IP
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Hostname", "MAC", "IP"])
        self.table.cellClicked.connect(self.cell_clicked)
                                        
        # Browser pane
        self.browser = QWebEngineView()
        self.browser.setPage(InsecureWebPage(self.browser))
                                                                            
        # Assemble left pane
        left.addWidget(self.scan_button)
        left.addWidget(self.table)
                                          
        # Main layout
        layout.addLayout(left, 30)
        layout.addWidget(self.browser, 70)
        self.setLayout(layout)
                                                          
    # Network scan + table population
    def do_scan(self):
        entries = scan_network()
        self.table.setRowCount(0)

        for ip, mac in entries:

            # Filter only configured prefixes
            if not any(mac.startswith(p) for p in MAC_PREFIXES):
                continue

            hostname = generate_hostname(mac)
                                                                
            row = self.table.rowCount()
            self.table.insertRow(row)
                                                       
            # --- Hostname column 
            hostname_item = QTableWidgetItem(hostname)
            hostname_item.setForeground(Qt.blue)
            hostname_item.setData(Qt.UserRole, f"https://{hostname}/commissioning/welcome.html")
            self.table.setItem(row, 0, hostname_item)
                                                             
            # --- MAC column 
            mac_item = QTableWidgetItem(mac)
            mac_item.setForeground(Qt.blue)
            mac_item.setData(Qt.UserRole, f"https://{hostname}/commissioning/welcome.html")  # MAC loads hostname page
            self.table.setItem(row, 1, mac_item)
                                                                   
            # --- IP column 
            if is_link_local(ip):
                ip_item = QTableWidgetItem("(link-local)")
            else:  
                ip_item = QTableWidgetItem(ip)
                ip_item.setForeground(Qt.blue)
                ip_item.setData(Qt.UserRole, f"https://{ip}/commissioning/welcome.html")  # IP loads direct page
                                                         
            self.table.setItem(row, 2, ip_item)
                      
                            
    # Clicking a table cell loads URL
    def cell_clicked(self, row, col):
        item = self.table.item(row, col)
        if not item:
            return
                                            
        url = item.data(Qt.UserRole)
        if url:
            print("Loading:", url)
            self.browser.setUrl(QUrl(url)) 
    '''
    def cell_clicked(self, row, col):
        item = self.table.item(row, col)
        if not item:
            return
                      
        url = item.data(Qt.UserRole)
        if url:
            print(f"Loading: {url}")
            self.browser.setUrl(url)
    '''             
                  
                                   
# Main
if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = OptoScanner()
    win.show()
    sys.exit(app.exec_())
               
