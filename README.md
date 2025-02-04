# Network File Transfer

## 📌 Project Description

This project implements a **secure file transfer system** over a TCP connection using **AES encryption**. It consists of two main components:

Sender (`sender.py`): Splits a file into chunks, encrypts each chunk, and transmits it to the receiver.

Receiver (`receiver.py`): Receives, decrypts, and reassembles the transmitted file.

## 🚀 Features

1. [x] Secure file transfer with **AES encryption** (CBC mode)
2. [x] File integrity verification using **SHA-256 checksums**
3. [x] Packet retransmission for lost or corrupted packets
4. [x] Supports **small and large file transfers**
5. [x] TCP-based communication

## 📂 Project Structure

📁 Network-File-Transfer

├── sender.py       # Sender script to send encrypted files

├── receiver.py     # Receiver script to receive and decrypt files

├── README.md       # Documentation

├── requirements.txt # Dependencies list

## 🔧 Setup Instructions

1. **Prerequisites**

Ensure you have Python 3.6+ installed. Install dependencies:

`pip install -r requirements.txt`

2. **Running the Receiver**

On the receiver machine, start the receiver:

`python receiver.py <output_file> <port> <encryption_key>`

Example:

`python receiver.py received_file.txt 12345 e216786da128ce094a0561843715ccf0`

3. **Running the Sender**

On the sender machine, send the file:

`python sender.py <file_path> <destination_ip> <port> <encryption_key>`

Example:

`python sender.py input.txt 192.168.1.70 12345 e216786da128ce094a0561843715ccf0`

## 🔑 Encryption Details

**AES-256 CBC Mode** is used for encryption.

A **random IV (Initialization Vector)** is generated for each packet.

The key must be a **32-character hexadecimal string**.

## 🛠 Troubleshooting

* **Error: Connection refused**

  * Ensure the **receiver is running** before starting the sender.

* **Checksum mismatch & packet loss**

  * The system will **automatically request retransmissions**.

* **Encryption key mismatch**

  * Ensure the **same key is used** on both sender and receiver.

## 📜 License

This project is open-source and available under the **MIT License**.

## 🤝 Acknowledgments

Inspired by **secure file transfer protocols**.

Uses **PyCryptodome** for encryption.