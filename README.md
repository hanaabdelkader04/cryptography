# Secure Chat Application

A secure and interactive chat application built using Python that supports encrypted communication between multiple clients and a central server. 
The application is designed with modern cryptographic standards to ensure the confidentiality and security of user communications.
This project demonstrates real-world concepts of secure programming, including encryption, password hashing, key exchange protocols, and multithreading for handling simultaneous client connections.

---

## Features

### User Authentication
- **Registration**:
  - Users can create accounts with secure password hashing and salting using the SHA-256 algorithm.
  - User credentials are stored in an encrypted JSON file to ensure data security.
- **Login**:
  - Existing users can log in to access the chat room.
  - Authentication is performed securely to prevent unauthorized access.

---

### Encrypted Communication
- **AES Encryption**:
  - Messages are encrypted using AES encryption in CFB mode.
  - The encryption key is dynamically generated for each session using the Diffie-Hellman key exchange protocol.
- **Secure Message Handling**:
  - All messages are transmitted over the network in an encrypted format, ensuring that they cannot be intercepted or read by unauthorized parties.

---

### Real-Time Chat
- Clients can send and receive messages in real time.
- The server broadcasts messages to all connected clients except the sender.
- A GUI-based interface allows users to interact seamlessly with the chat room.

---

### Chat History
- Encrypted chat history is saved for every conversation between users in the `chat_histories/` directory.
- Each user's chat history is stored securely, and the messages are encrypted with their respective session keys.

---

### Client Disconnection
- Users can exit the chat room by pressing the "X" button on the GUI or entering `#exit` in the message box.
- The server and other connected clients are notified when a user exits.






---



## Technologies Used

### Programming Language
- **Python**: The application is written entirely in Python for simplicity and ease of development.

---

### Cryptographic Libraries
- **cryptography**:
  - Used for implementing AES encryption and PKCS7 padding.
  - Ensures secure message transmission across the network.
- **hashlib**:
  - Provides secure password hashing with SHA-256.

---

### Networking
- **socket**:
  - Facilitates communication between clients and the server using TCP.
- **select**:
  - Enables efficient handling of multiple connections, ensuring smooth operation even with many clients.

---

### GUI
- **Tkinter**:
  - Powers the graphical interface for the client, providing an intuitive and user-friendly experience.

---

### Multithreading
- **threading**:
  - Allows the server to handle multiple clients simultaneously.
  - Ensures uninterrupted operation for all connected clients, even during high traffic.

---

## Installation

### Prerequisites
1. Install **Python 3.8** or higher on your system.
2. Install the required cryptography library:
   
   ```bash
   pip install cryptography
