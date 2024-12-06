import socket
import threading
import os
import json
import base64
import hashlib
import secrets
from tkinter import *
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

MAX_LEN = 200
DH_P = 23  # Diffie-Hellman parameter (use a real one in production)
DH_G = 5   # Diffie-Hellman generator


class ChatClient:
    def __init__(self, root):
        self.root = root
        self.client_socket = None
        self.aes_key = None
        self.username = ""

        # Frames for GUI
        self.login_frame = Frame(root, padx=20, pady=20)
        self.chat_frame = Frame(root, padx=20, pady=20)

        self.create_login_gui()

    def create_login_gui(self):
        """Create the login and register window."""
        self.login_frame.pack()

        Label(self.login_frame, text="Username:").grid(row=0, column=0, sticky=W, pady=5)
        self.username_entry = Entry(self.login_frame, width=30)
        self.username_entry.grid(row=0, column=1, pady=5)

        Label(self.login_frame, text="Password:").grid(row=1, column=0, sticky=W, pady=5)
        self.password_entry = Entry(self.login_frame, show="*", width=30)
        self.password_entry.grid(row=1, column=1, pady=5)

        Button(self.login_frame, text="Login", command=self.login, width=15).grid(row=2, column=0, pady=10)
        Button(self.login_frame, text="Register", command=self.register, width=15).grid(row=2, column=1, pady=10)

    def create_chat_gui(self):
        """Create the chat window."""
        self.login_frame.pack_forget()  # Hide login frame
        self.chat_frame.pack()

        self.chat_text = Text(self.chat_frame, state=DISABLED, height=20, width=50)
        self.chat_text.grid(row=0, column=0, columnspan=2, pady=10)

        self.message_entry = Entry(self.chat_frame, width=40)
        self.message_entry.grid(row=1, column=0, pady=10)

        Button(self.chat_frame, text="Send", command=self.send_message, width=10).grid(row=1, column=1, pady=10)

    def perform_key_exchange(self):
        """Perform Diffie-Hellman key exchange with the server."""
        client_private_key = secrets.randbelow(DH_P)
        client_public_key = pow(DH_G, client_private_key, DH_P)

        # Send public key and receive server's public key
        server_public_key = int(self.client_socket.recv(MAX_LEN).decode())
        self.client_socket.sendall(str(client_public_key).encode())

        # Compute the shared secret and derive AES key
        shared_secret = pow(server_public_key, client_private_key, DH_P)
        self.aes_key = hashlib.sha256(str(shared_secret).encode()).digest()

    def login(self):
        """Handle user login."""
        self.username = self.username_entry.get()
        password = self.password_entry.get()

        if not self.username or not password:
            messagebox.showwarning("Input Error", "Username and password cannot be empty")
            return

        credentials = json.dumps({"username": self.username, "password": password, "action": "login"})
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(('127.0.0.1', 10000))  # Connect to the server

        try:
            self.perform_key_exchange()
            self.client_socket.sendall(credentials.encode())
            response = self.client_socket.recv(MAX_LEN).decode()

            if response == "LOGIN_SUCCESS":
                messagebox.showinfo("Success", "Login successful!")
                self.create_chat_gui()
                threading.Thread(target=self.receive_messages, daemon=True).start()
            else:
                messagebox.showerror("Login Failed", "Invalid username or password.")
                self.client_socket.close()
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
            self.client_socket.close()

    def register(self):
        """Handle user registration."""
        self.username = self.username_entry.get()
        password = self.password_entry.get()

        if not self.username or not password:
            messagebox.showwarning("Input Error", "Username and password cannot be empty")
            return

        credentials = json.dumps({"username": self.username, "password": password, "action": "register"})
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(('127.0.0.1', 10000))  # Connect to the server

        try:
            self.perform_key_exchange()
            self.client_socket.sendall(credentials.encode())
            response = self.client_socket.recv(MAX_LEN).decode()

            if response == "REGISTER_SUCCESS":
                messagebox.showinfo("Success", "Registration successful!")
                self.create_chat_gui()
                threading.Thread(target=self.receive_messages, daemon=True).start()
            else:
                messagebox.showerror("Registration Failed", "Username already exists.")
                self.client_socket.close()
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
            self.client_socket.close()

    def send_message(self):
        """Send a message to the server and display it locally."""
        message = self.message_entry.get()
        if message:
            # Display the sent message locally
            self.chat_text.config(state=NORMAL)
            self.chat_text.insert(END, f"You: {message}\n")
            self.chat_text.config(state=DISABLED)

            # Encrypt and send the message
            encrypted_message = self.encrypt_message(message)
            self.client_socket.sendall(encrypted_message.encode())
            self.message_entry.delete(0, END)

    def receive_messages(self):
        """Receive messages from the server."""
        while True:
            try:
                encrypted_message = self.client_socket.recv(MAX_LEN)  # Receive raw bytes
                message = self.decrypt_message(encrypted_message)  # Decrypt the message
                self.chat_text.config(state=NORMAL)
                self.chat_text.insert(END, f"{message}\n")  # Display received message
                self.chat_text.config(state=DISABLED)
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    def encrypt_message(self, message):
        """Encrypt a message using AES."""
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_message = padder.update(message.encode()) + padder.finalize()

        cipher = Cipher(algorithms.AES(self.aes_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

        return base64.b64encode(iv + encrypted_message).decode()

    def decrypt_message(self, encrypted_message):
        """Decrypt a message using AES."""
        encrypted_data = base64.b64decode(encrypted_message)  # Decode from base64
        iv = encrypted_data[:16]
        encrypted_message = encrypted_data[16:]

        cipher = Cipher(algorithms.AES(self.aes_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        message = unpadder.update(padded_message) + unpadder.finalize()

        return message.decode('utf-8')  # Decode bytes to string


# Run the GUI
root = Tk()
root.title("Chat Application")
root.geometry("400x500")
client = ChatClient(root)
root.mainloop()
