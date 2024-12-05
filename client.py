import socket
import threading
import sys
import signal
import time
import json

MAX_LEN = 200
exit_flag = False

def send_message():
    global exit_flag
    while not exit_flag:
        try:
            message = input("You: ")
            client_socket.sendall(message.encode())
            if message == "#exit":
                exit_flag = True
                client_socket.close()
                return
        except OSError:
            return

def recv_message():
    global exit_flag
    while not exit_flag:
        try:
            message = client_socket.recv(MAX_LEN).decode()
            if not message:
                continue
            print(f"\r{message}")
            print("You: ", end="", flush=True)
        except:
            break
    print("Disconnected from server.")

def signal_handler(sig, frame):
    global exit_flag
    if not exit_flag:
        print("\nDisconnecting...")
        exit_flag = True
        try:
            client_socket.sendall("#exit".encode())
        except OSError:
            pass
        client_socket.close()
        sys.exit(0)

def login_or_register():
    while True:
        choice = input("Type '1' to Login or '2' to Create a new account: ")
        if choice not in ('1', '2'):
            print("Invalid choice. Please enter '1' or '2'.")
            continue
        username = input("Enter your username: ")
        password = input("Enter your password: ")
        credentials = json.dumps({
            "username": username,
            "password": password,
            "action": "login" if choice == '1' else "register"
        })
        client_socket.sendall(credentials.encode())
        response = client_socket.recv(MAX_LEN).decode()
        if response == "LOGIN_SUCCESS":
            print("\n\t  ====== Welcome to the chat-room ======   ")
            return True
        elif response == "REGISTER_SUCCESS":
            print("Account created successfully. You are now logged in!")
            return True
        elif response == "LOGIN_FAILED":
            print("Login failed. Check your credentials.")
        elif response == "REGISTER_FAILED":
            print("Username already exists. Try again.")
        else:
            print("Unknown error occurred.")
    return False

def main():
    global client_socket
    signal.signal(signal.SIGINT, signal_handler)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('127.0.0.1', 10000)
    try:
        client_socket.connect(server_address)
    except ConnectionRefusedError:
        print("Failed to connect to the server. Is it running?")
        sys.exit(1)

    if not login_or_register():
        client_socket.close()
        sys.exit(0)

    threading.Thread(target=send_message, daemon=True).start()
    threading.Thread(target=recv_message, daemon=True).start()

    try:
        while not exit_flag:
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)

if __name__ == "__main__":
    main()