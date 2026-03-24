"""
Author: Howard Huang
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

# Imports (Step ii)
import socket
import threading
import sqlite3
import os
import platform
import datetime


# Python version and OS name (Step iii)
print("Python Version:", platform.python_version())
print("Operating System:", os.name, end="\n\n")


# Key/value pairs (dictionary) of port #s and their service (Step iv)
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}
DB_NAME = "scan_history.db"

# NetworkTool class w/ constructor, getter, setter & destructor (Step v)
class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    """
    The @property and @target.setter decorators offers encapsulation and hides implementation details.
    As the '__target' access is private, a getter is necessary to access the property outside of the class definition.
    The setter is beneficial to apply logic on property, in this case non-empty string.
    """
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, target):
        if isinstance(target, str):
            if len(target) > 0:
                self.__target = target
            else:
                print("Error: Target cannot be empty.")
        else:
            print("Error: Target must be a string.")

    def __del__(self):
        print("NetworkTool instance destroyed.")



# Q1: How does PortScanner reuse code from NetworkTool?
"""
PortScanner first inherits NetworkTools to be able to call super() and access any non-private properties and methods.
Within its constructor, the child class calls the parent class constructor and the destructor does the same.
"""
# PortScanner child extends NetworkTool (Step vi)
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed.")
        super().__del__()

    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        """
        This method uses connect_ex() in the socket module to connect to an address.
        If that address is incorrect, or it takes too long, I would need the try-except to gracefully handle the error instead of crashing the program.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))

            status = "Open" if result == 0 else "Closed"

            service_name = common_ports[port] if port in common_ports else "Unknown"

            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()

        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    def get_open_ports(self):
        open_ports = [port for port in self.scan_results if port[1] == "Open"]
        return open_ports


    # Q2: Why do we use threading instead of scanning one port at a time?
    """
    Threading allows this program/process to concurrently scan ports to save time and take advantage of multiple threads in a CPU.
    Since the amount of ports range between 1–65535, it would take a significantly longer time if scanning was done sequentially. 
    """
    def scan_range(self, start_port, end_port):
        threads = []
        # +1 to end range to make it inclusive
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    # save results of scan into DB (Step vii)
    def save_results(self, target, results):
        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("""CREATE TABLE IF NOT EXISTS scans
                              (
                                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                                  target TEXT,
                                  port INTEGER,
                                  status TEXT,
                                  service TEXT,
                                  scan_date TEXT
                              )""")
            for result in results:
                cursor.execute(
                    """INSERT INTO scans (target, port, status, service, scan_date)
                       VALUES (?, ?, ?, ?, ?)""",
                    (target, result[0], result[1], result[2], str(datetime.datetime.now()))
                )
            conn.commit()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        finally:
            conn.close()

    # Load results from past scans (Step viii)
    def load_past_scans(self):
        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("""SELECT * FROM scans""")
            rows = cursor.fetchall()
            for row in rows:
                print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")
        except:
            print("No past scans found")
        finally:
            conn.close()

# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    # Get user input of IP & port ranges (Step ix)
    try:
        ip = input("Enter a target IP Address (Default: 127.0.0.1): ") or "127.0.0.1"
        while True:
            start_port = int(input("Enter a starting port between 1~1024: "))
            end_port = int(input("Enter an ending port between the starting port and 1024: "))
            if not (1 <= start_port < 1024 and 1 <= end_port <= 1024):
                print("Ports must be between 1 and 1024\n")
                continue

            if not start_port <= end_port:
                print("End port must be greater than or equal to Start port\n")
                continue
            break
    except ValueError:
        print("Invalid input. Please enter a valid integer.")


    # Perform port scanning & results (Step x)
    ps = PortScanner(ip)
    print(f"Scanning {ip} from port {start_port} to {end_port}...")
    ps.scan_range(start_port, end_port)
    results = ps.get_open_ports()
    print(f"--- Scan Results for {ip} ---")
    for result in results:
        print(f"Port {result[0]}: {result[1]} ({result[2]})")
    print("-" * 6)
    print(f"Total open ports found: {len(results)}.\n")

    ps.save_results(ip, results)

    inp = input("Would you like to see past scan history? (yes/no): ")
    if inp == "yes":
        ps.load_past_scans()


# Q5: New Feature Proposal
"""
A feature that can be added would be displaying scan results from 'scan_history.db'. 
We already have a retrieval that displays everything but what if the user wants to display all results with a known port service (e.g. filter results by "FTP")
List comprehension could be used with the existing method, load_past_scans(), to filter the results (a query can also achieve this too).
E.g. filtered_rows = [row for row in rows if row[4] == service_name_filter]
"""
