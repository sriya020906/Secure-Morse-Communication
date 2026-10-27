
"""
STM32 Morse messaging control panel and serial bridge.

Install:
    python -m pip install pyserial

Connections:
    Laptop Bluetooth COM <-> HC-05 <-> Sender STM32 USART1
    Laptop USB COM       <-> CP2102 <-> Receiver STM32 USART1

Protocol:
    GUI -> Sender:   TEXT:<message>
    Sender -> GUI:   MSG:<duration_ms>:<morse>
    GUI -> Receiver: MSG:<duration_ms>:<morse>
    Receiver -> GUI: READY
                     CIPHERTEXT:<ciphertext>
                     ACK:RECEIVED
                     AUTH:OK:<plaintext>
                     AUTH:DENIED
                     ERR:<message>
    GUI -> Receiver: PIN:<digits>

The sender firmware must accept TEXT: and READY over Bluetooth USART1.
The receiver firmware must accept MSG: and PIN: over USART1.
"""

import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox

import serial
import serial.tools.list_ports


BAUD_RATE = 9600
SERIAL_TIMEOUT = 0.2
WRITE_TIMEOUT = 1


class App(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Secure Store-and-Forward Morse Messaging")
        self.geometry("800x620")
        self.minsize(700, 500)

        self.bt_ser = None
        self.rx_ser = None

        self.reader_threads = []
        self.stop_event = threading.Event()
        self.write_lock = threading.Lock()
        self.ui_queue = queue.Queue()

        self.status = tk.StringVar(value="Disconnected")
        self.bt_port = tk.StringVar()
        self.rx_port = tk.StringVar()
        self.message = tk.StringVar()
        self.pin = tk.StringVar()

        self.cipher = tk.StringVar(
            value="No ciphertext received yet"
        )
        self.auth = tk.StringVar(
            value="Waiting for receiver"
        )
        self.plain = tk.StringVar(
            value="Plaintext is locked until authentication succeeds"
        )

        self._build()
        self.refresh_ports()

        self.after(100, self.process_ui_queue)
        self.protocol("WM_DELETE_WINDOW", self.close)

    # ---------------------------------------------------------
    # GUI
    # ---------------------------------------------------------

    def _build(self):
        ports = ttk.LabelFrame(
            self, text="Serial connections", padding=10
        )
        ports.pack(fill="x", padx=10, pady=8)

        ttk.Label(
            ports, text="Sender Bluetooth COM:"
        ).grid(row=0, column=0, sticky="w", padx=4, pady=4)

        self.bt_box = ttk.Combobox(
            ports,
            textvariable=self.bt_port,
            width=18,
            state="readonly",
        )
        self.bt_box.grid(row=0, column=1, padx=4, pady=4)

        ttk.Label(
            ports, text="Receiver CP2102 COM:"
        ).grid(row=1, column=0, sticky="w", padx=4, pady=4)

        self.rx_box = ttk.Combobox(
            ports,
            textvariable=self.rx_port,
            width=18,
            state="readonly",
        )
        self.rx_box.grid(row=1, column=1, padx=4, pady=4)

        ttk.Button(
            ports,
            text="Refresh ports",
            command=self.refresh_ports,
        ).grid(row=0, column=2, padx=8, pady=4)

        ttk.Button(
            ports,
            text="Connect both",
            command=self.connect,
        ).grid(row=0, column=3, padx=4, pady=4)

        ttk.Button(
            ports,
            text="Disconnect",
            command=self.disconnect,
        ).grid(row=1, column=3, padx=4, pady=4)

        ttk.Label(
            ports, textvariable=self.status
        ).grid(
            row=2,
            column=0,
            columnspan=4,
            sticky="w",
            padx=4,
            pady=5,
        )

        tabs = ttk.Notebook(self)
        tabs.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=(0, 10),
        )

        sender_tab = ttk.Frame(tabs, padding=14)
        receiver_tab = ttk.Frame(tabs, padding=14)

        tabs.add(sender_tab, text="Sender")
        tabs.add(receiver_tab, text="Receiver / Authentication")

        ttk.Label(
            sender_tab,
            text="Message (A–Z, digits, and spaces):",
        ).pack(anchor="w")

        ttk.Entry(
            sender_tab,
            textvariable=self.message,
        ).pack(fill="x", pady=8)

        ttk.Button(
            sender_tab,
            text="Send message to sender STM32",
            command=self.send_message,
        ).pack(anchor="w")

        ttk.Label(
            sender_tab,
            text="Morse timing is selected using the sender potentiometer.",
        ).pack(anchor="w", pady=8)

        ttk.Label(
            sender_tab, text="Device log:"
        ).pack(anchor="w")

        self.log = tk.Text(
            sender_tab,
            height=16,
            wrap="word",
            state="disabled",
        )
        self.log.pack(
            fill="both",
            expand=True,
            pady=(4, 0),
        )

        ttk.Label(
            receiver_tab,
            text="Ciphertext received from receiver:",
        ).pack(anchor="w")

        ttk.Label(
            receiver_tab,
            textvariable=self.cipher,
            wraplength=680,
        ).pack(anchor="w", pady=8)

        ttk.Label(
            receiver_tab,
            text="Demonstration PIN:",
        ).pack(anchor="w")

        ttk.Entry(
            receiver_tab,
            textvariable=self.pin,
            show="*",
        ).pack(anchor="w", pady=5)

        ttk.Button(
            receiver_tab,
            text="Verify PIN on receiver STM32",
            command=self.send_pin,
        ).pack(anchor="w")

        ttk.Label(
            receiver_tab,
            text="Authentication status:",
        ).pack(anchor="w", pady=(14, 2))

        ttk.Label(
            receiver_tab,
            textvariable=self.auth,
            wraplength=680,
        ).pack(anchor="w")

        ttk.Label(
            receiver_tab,
            text="Plaintext:",
        ).pack(anchor="w", pady=(14, 2))

        ttk.Label(
            receiver_tab,
            textvariable=self.plain,
            wraplength=680,
        ).pack(anchor="w")

        ttk.Label(
            receiver_tab,
            text=(
                "Prototype only: KEY='STM' is a weak demonstration "
                "cipher; the PIN protocol is not production-secure."
            ),
            wraplength=680,
        ).pack(anchor="w", pady=16)

    # ---------------------------------------------------------
    # Serial port selection and connection
    # ---------------------------------------------------------

    def refresh_ports(self):
        ports = sorted(
            p.device
            for p in serial.tools.list_ports.comports()
        )

        self.bt_box["values"] = ports
        self.rx_box["values"] = ports

        if self.bt_port.get() not in ports:
            self.bt_port.set("")

        if self.rx_port.get() not in ports:
            self.rx_port.set("")

        self.add_log(
            "Available COM ports: "
            + (", ".join(ports) if ports else "none found")
        )

    def connect(self):
        if self.bt_ser is not None or self.rx_ser is not None:
            messagebox.showwarning(
                "Already connected",
                "Disconnect before connecting again.",
            )
            return

        bt = self.bt_port.get()
        rx = self.rx_port.get()

        if not bt or not rx:
            messagebox.showerror(
                "Select ports",
                "Select the sender Bluetooth COM and receiver CP2102 COM.",
            )
            return

        if bt == rx:
            messagebox.showerror(
                "Invalid selection",
                "Select two different COM ports.",
            )
            return

        try:
            self.stop_event.clear()

            self.bt_ser = serial.Serial(
                port=bt,
                baudrate=BAUD_RATE,
                timeout=SERIAL_TIMEOUT,
                write_timeout=WRITE_TIMEOUT,
            )

            self.rx_ser = serial.Serial(
                port=rx,
                baudrate=BAUD_RATE,
                timeout=SERIAL_TIMEOUT,
                write_timeout=WRITE_TIMEOUT,
            )

            self.reader_threads = [
                threading.Thread(
                    target=self.read_loop,
                    args=("sender", self.bt_ser),
                    daemon=True,
                ),
                threading.Thread(
                    target=self.read_loop,
                    args=("receiver", self.rx_ser),
                    daemon=True,
                ),
            ]

            for thread in self.reader_threads:
                thread.start()

            self.status.set(
                f"Connected: sender {bt}, receiver {rx}"
            )

            self.add_log(
                f"Both serial ports opened at {BAUD_RATE} baud."
            )
            self.add_log(
                "Waiting for receiver READY. Reset the receiver "
                "if READY does not appear."
            )

        except Exception as exc:
            self.close_serial_ports()
            self.status.set("Connection failed")
            messagebox.showerror(
                "Connection failed",
                str(exc),
            )

    def disconnect(self):
        self.close_serial_ports()
        self.status.set("Disconnected")
        self.add_log("Serial connections closed.")

    def close_serial_ports(self):
        self.stop_event.set()

        with self.write_lock:
            for port in (self.bt_ser, self.rx_ser):
                try:
                    if port is not None and port.is_open:
                        port.close()
                except Exception:
                    pass

        self.bt_ser = None
        self.rx_ser = None

    # ---------------------------------------------------------
    # Serial writing
    # ---------------------------------------------------------

    def write_port(self, port, line, log_label="PC → device"):
        if port is None or not port.is_open:
            self.ui_queue.put(
                ("log", f"Cannot send '{line}': serial port is closed.")
            )
            return False

        try:
            data = (line + "\n").encode("ascii", errors="strict")

            with self.write_lock:
                if not port.is_open:
                    return False

                port.write(data)
                port.flush()

            self.ui_queue.put(
                ("log", f"{log_label}: {line}")
            )
            return True

        except (serial.SerialException, OSError, UnicodeEncodeError) as exc:
            self.ui_queue.put(
                ("log", f"Serial write error: {exc}")
            )
            return False

    # ---------------------------------------------------------
    # GUI commands
    # ---------------------------------------------------------

    def send_message(self):
        text = self.message.get().strip().upper()

        if not text:
            messagebox.showwarning(
                "Message",
                "Enter a message first.",
            )
            return

        allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ")

        if any(ch not in allowed for ch in text):
            messagebox.showwarning(
                "Unsupported character",
                "Use only A–Z, digits, and spaces.",
            )
            return

        if self.bt_ser is None or not self.bt_ser.is_open:
            messagebox.showwarning(
                "Not connected",
                "Connect both serial ports first.",
            )
            return

        # Send TEXT only to the sender Bluetooth UART.
        self.write_port(
            self.bt_ser,
            "TEXT:" + text,
        )

    def send_pin(self):
        pin = self.pin.get().strip()

        if not pin:
            messagebox.showwarning(
                "PIN",
                "Enter the demonstration PIN.",
            )
            return

        if not pin.isdigit():
            messagebox.showwarning(
                "PIN",
                "Enter digits only.",
            )
            return

        if self.rx_ser is None or not self.rx_ser.is_open:
            messagebox.showwarning(
                "Not connected",
                "Connect both serial ports first.",
            )
            return

        if self.write_port(
            self.rx_ser,
            "PIN:" + pin,
            log_label="PC → receiver",
        ):
            self.auth.set(
                "PIN request sent; waiting for receiver response."
            )
            self.add_log("PIN value hidden in log.")

    # ---------------------------------------------------------
    # Serial reading threads
    # ---------------------------------------------------------

    def read_loop(self, source, port):
        while not self.stop_event.is_set():
            try:
                raw = port.readline()

                if not raw:
                    continue

                line = raw.decode(
                    "ascii",
                    errors="replace",
                ).strip()

                if line:
                    self.ui_queue.put(
                        ("line", source, line)
                    )

            except (serial.SerialException, OSError) as exc:
                if not self.stop_event.is_set():
                    self.ui_queue.put(
                        (
                            "log",
                            f"{source.upper()} serial read error: {exc}",
                        )
                    )
                break

    # ---------------------------------------------------------
    # Route incoming messages
    # ---------------------------------------------------------

    def handle_line(self, source, line):
        self.add_log(f"{source.upper()} → PC: {line}")

        if source == "sender":
            self.handle_sender_line(line)

        elif source == "receiver":
            self.handle_receiver_line(line)

    def handle_sender_line(self, line):
        if line.startswith("MSG:"):
            # Sender has encoded the message into a Morse frame.
            # Forward that frame to the receiver USB UART.
            self.write_port(
                self.rx_ser,
                line,
                log_label="PC → receiver",
            )

        elif line.startswith("STATUS:"):
            # Status is for the GUI only. Never forward it to receiver.
            self.status.set(line)

        elif line.startswith("CIPHERTEXT:"):
            self.cipher.set(line[len("CIPHERTEXT:"):])

        elif line == "ACK:RECEIVED":
            self.add_log("Acknowledgement received from sender.")

        elif line == "AUTH:DENIED":
            self.auth.set("DENIED — plaintext remains locked")
            self.plain.set("Plaintext withheld")

        elif line.startswith("AUTH:OK:"):
            self.auth.set("AUTHENTICATED")
            self.plain.set(line[len("AUTH:OK:"):])

        elif line.startswith("ERR:"):
            self.add_log("Sender error: " + line)

        elif line == "READY":
            # Normally READY originates at the receiver. If the sender
            # echoes it, don't forward it back to receiver.
            self.add_log("Sender reported READY.")

        else:
            self.add_log("Unrecognized sender line: " + line)

    def handle_receiver_line(self, line):
        if line == "READY":
            # This is essential: the sender uses READY to allow sending.
            self.add_log(
                "Receiver READY received; forwarding to sender."
            )
            self.write_port(
                self.bt_ser,
                "READY",
                log_label="PC → sender",
            )

        elif line.startswith("CIPHERTEXT:"):
            self.cipher.set(line[len("CIPHERTEXT:"):])
            self.write_port(
                self.bt_ser,
                line,
                log_label="PC → sender",
            )

        elif line == "ACK:RECEIVED":
            self.add_log("Receiver acknowledged the message.")
            self.write_port(
                self.bt_ser,
                line,
                log_label="PC → sender",
            )

        elif line == "AUTH:DENIED":
            self.auth.set("DENIED — plaintext remains locked")
            self.plain.set("Plaintext withheld")
            self.write_port(
                self.bt_ser,
                line,
                log_label="PC → sender",
            )

        elif line.startswith("AUTH:OK:"):
            self.auth.set("AUTHENTICATED")
            self.plain.set(line[len("AUTH:OK:"):])
            self.write_port(
                self.bt_ser,
                line,
                log_label="PC → sender",
            )

        elif line.startswith("ERR:"):
            self.add_log("Receiver error: " + line)
            self.write_port(
                self.bt_ser,
                line,
                log_label="PC → sender",
            )

        else:
            self.add_log(
                "Unrecognized receiver response: " + line
            )

    # ---------------------------------------------------------
    # GUI log and event queue
    # ---------------------------------------------------------

    def process_ui_queue(self):
        try:
            while True:
                item = self.ui_queue.get_nowait()

                if item[0] == "log":
                    self.add_log(item[1])

                elif item[0] == "line":
                    self.handle_line(item[1], item[2])

        except queue.Empty:
            pass

        if self.winfo_exists():
            self.after(100, self.process_ui_queue)

    def add_log(self, line):
        self.log.configure(state="normal")
        self.log.insert("end", line + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def close(self):
        self.close_serial_ports()
        self.destroy()


if __name__ == "__main__":
    App().mainloop()
