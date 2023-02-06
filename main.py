# import tkinter as tk
# import nmap

# # Define the scan function


# def scan():
#     # Get the target host and port from the GUI
#     target_host = host_entry.get()
#     target_port = port_entry.get()

#     # Initialize the nmap scanner
#     nm = nmap.PortScanner()

#     # Scan the target host on the specified port
#     nm.scan(target_host, target_port)

#     # Get information about the target host
#     host = nm.all_hosts()[0]
#     result_text.insert(tk.END, f"Host: {host} ({nm[host].hostname()})\n")
#     result_text.insert(tk.END, f"State: {nm[host].state()}\n")

#     # Get information about the open ports on the target host
#     for port in nm[host].all_tcp():
#         result_text.insert(
#             tk.END, f"Port {port}: {nm[host]['tcp'][port]['name']} ({nm[host]['tcp'][port]['state']})\n")


# # Create the GUI window
# root = tk.Tk()
# root.title("Nmap Scanner")

# # Create the host entry widget
# host_label = tk.Label(root, text="Target Host:")
# host_label.pack()
# host_entry = tk.Entry(root)
# host_entry.pack()

# # Create the port entry widget
# port_label = tk.Label(root, text="Target Port:")
# port_label.pack()
# port_entry = tk.Entry(root)
# port_entry.pack()

# # Create the scan button widget
# scan_button = tk.Button(root, text="Scan", command=scan)
# scan_button.pack()

# # Create the result text widget
# result_text = tk.Text(root)
# result_text.pack()

# # Start the GUI event loop
# root.mainloop()


# import nmap

# # Initialize the nmap scanner
# nm = nmap.PortScanner()

# # Scan the target host on ports 22 and 80
# nm.scan('154.0.161.161', '22,80')

# # Get information about the target host
# host = nm.all_hosts()[0]
# print(f"Host: {host} ({nm[host].hostname()})")
# print(f"State: {nm[host].state()}")

# # Get information about the open ports on the target host
# for port in nm[host].all_tcp():
#     print(
#         f"Port {port}: {nm[host]['tcp'][port]['name']} ({nm[host]['tcp'][port]['state']})")

import sys
import nmap
import os
from PyQt5 import QtWidgets, QtGui
from PyQt5.QtWidgets import QMainWindow, QLabel, QGridLayout, QWidget, QTextEdit, QPushButton, QLineEdit


class NmapScanner(QMainWindow):

    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle("Nmap Scanner")
        self.setGeometry(100, 100, 400, 300)

        # create grid layout and set as central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        grid_layout = QGridLayout()
        central_widget.setLayout(grid_layout)

        # add target label and line edit
        target_label = QLabel("Target:")
        grid_layout.addWidget(target_label, 0, 0)
        self.target_line_edit = QLineEdit()
        grid_layout.addWidget(self.target_line_edit, 0, 1)

        # add port label and line edit
        port_label = QLabel("Port:")
        grid_layout.addWidget(port_label, 1, 0)
        self.port_line_edit = QLineEdit()
        grid_layout.addWidget(self.port_line_edit, 1, 1)

        # add scan button
        scan_button = QPushButton("Scan")
        scan_button.clicked.connect(self.scan)
        grid_layout.addWidget(scan_button, 2, 0)

        # add text edit
        self.text_edit = QTextEdit()
        grid_layout.addWidget(self.text_edit, 3, 0, 1, 2)

    def scan(self):
        target = self.target_line_edit.text()
        port = self.port_line_edit.text()

        # initialize Nmap scanner
        nm = nmap.PortScanner()

        # scan target
        nm.scan(target, port)

        # get all hosts
        hosts = nm.all_hosts()

        # iterate over all hosts and display their status
        for host in hosts:
            host_status = nm[host].state()
            self.text_edit.append("Host: {0} ({1})".format(host, host_status))

            # iterate over all open ports
            for port in nm[host]['tcp'].keys():
                port_status = nm[host]['tcp'][port]['state']
                self.text_edit.append(
                    "    Port: {0} ({1})".format(port, port_status))


app = QtWidgets.QApplication(sys.argv)
nmap_scanner = NmapScanner()
nmap_scanner.show()
sys.exit(app.exec_())
