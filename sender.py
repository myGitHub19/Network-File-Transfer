import socket  # Import socket module for network communication
import hashlib  # Import hashlib for computing checksums
import sys  # Import sys for command-line argument handling
import time  # Import time for adding delays
from Crypto.Cipher import AES  # Import AES for encryption
from Crypto.Util.Padding import pad  # Import padding utility for AES encryption


def calculate_checksum(data):
    """Calculate SHA-256 checksum of given data."""
    return hashlib.sha256(data).digest()


def encrypt_data(data, key):
    """Encrypt data using AES CBC mode."""
    cipher = AES.new(key, AES.MODE_CBC)  # Create AES cipher with given key in CBC mode
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))  # Encrypt and pad data
    return cipher.iv + ct_bytes  # Return IV concatenated with encrypted data


def send_file(file_path, destination_ip, destination_port, encryption_key):
    """Send a file to the receiver over a TCP socket with encryption."""

    # Read the entire file into memory
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Define chunk size considering overhead from sequence number and checksum
    chunk_size = 1400 - 6 - 32  # 1400 bytes minus 6 bytes for sequence and 32 bytes for checksum

    # Split file data into chunks
    data_chunks = [file_data[i:i + chunk_size] for i in range(0, len(file_data), chunk_size)]
    total_packets = len(data_chunks)  # Number of packets required

    # Ensure the file is not too large
    if total_packets > 10000:
        print("Error: File is too large. Reduce file size.")
        sys.exit(1)

    # Create a TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to receiver
        sock.connect((destination_ip, destination_port))
        print(f"✅ Connected to {destination_ip}:{destination_port}")

        # Send the header containing total number of packets
        header = f"HEAD:{total_packets}\n".encode()
        sock.sendall(header)
        print(f"📤 Sent header: {header.decode(errors='ignore').strip()}")

        # Send each chunk with a sequence number
        for i, chunk in enumerate(data_chunks):
            seq_num = str(i).zfill(5).encode()  # Format sequence number to 5 digits
            encrypted_chunk = encrypt_data(chunk, encryption_key)  # Encrypt chunk
            checksum = calculate_checksum(encrypted_chunk)  # Compute checksum
            payload = seq_num + b':' + encrypted_chunk + checksum  # Construct payload

            try:
                sock.sendall(payload)  # Send packet
                time.sleep(0.005)  # Small delay to prevent congestion
            except (BrokenPipeError, ConnectionResetError, socket.error) as e:
                print(f"⚠️ Error: Connection lost while sending packet {i}. Retrying... ({e})")
                sock.close()
                time.sleep(1)  # Short delay before reconnecting
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)  # Set timeout for reconnection
                try:
                    sock.connect((destination_ip, destination_port))
                    print("✅ Reconnected successfully. Resending packet...")
                    sock.sendall(payload)
                except ConnectionRefusedError:
                    print("❌ Error: Receiver is unavailable. Retrying in 3 seconds...")
                    time.sleep(3)

        print(f"✅ Sent {total_packets} packets to {destination_ip}:{destination_port}.")

        # Handle retransmissions based on receiver's feedback
        while True:
            try:
                ack = sock.recv(1024).decode().strip()  # Receive acknowledgment

                if ack == "ACK":
                    print("✅ Final acknowledgment received. Transfer complete. Exiting...")
                    break

                elif ack:  # If retransmission is requested
                    missing_packets = sorted(set(int(seq.strip()) for seq in ack.split(',')
                                                 if seq.strip().isdigit() and int(seq.strip()) < total_packets))

                    if not missing_packets:
                        print("⚠️ No valid retransmission requests. Stopping sender.")
                        break

                    print(f"🔄 Retransmitting packets: {missing_packets}")

                    for seq_num in missing_packets:
                        print(f"🔄 Retransmitting packet {seq_num}...")
                        payload = str(seq_num).zfill(5).encode() + b':' + encrypt_data(data_chunks[seq_num],
                                                                                       encryption_key) + calculate_checksum(
                            encrypt_data(data_chunks[seq_num], encryption_key))

                        try:
                            sock.sendall(payload)
                            time.sleep(0.005)
                        except (BrokenPipeError, ConnectionResetError, socket.error) as e:
                            print(
                                f"⚠️ Error: Connection lost during retransmission. Checking receiver availability... ({e})")
                            time.sleep(1)
                            try:
                                test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                test_sock.settimeout(5)
                                test_sock.connect((destination_ip, destination_port))
                                test_sock.close()
                                print("✅ Receiver is still available. Retrying...")
                            except ConnectionRefusedError:
                                print("❌ Receiver is no longer available. Stopping sender.")
                                break

            except (BrokenPipeError, ConnectionResetError, socket.error) as e:
                print(f"⚠️ Error: Connection lost during retransmission. Checking receiver availability... ({e})")
                time.sleep(1)
                try:
                    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_sock.settimeout(5)
                    test_sock.connect((destination_ip, destination_port))
                    test_sock.close()
                    print("✅ Receiver is still available. Retrying...")
                except ConnectionRefusedError:
                    print("❌ Receiver is no longer available. Stopping sender.")
                    break

    except Exception as e:
        print(f"❌ Error: {e}")

    finally:
        sock.close()


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python sender.py <file_path> <destination_ip> <destination_port> <encryption_key>")
        sys.exit(1)

    file_path = sys.argv[1]  # Get file path from command line
    destination_ip = sys.argv[2]  # Get destination IP
    destination_port = int(sys.argv[3])  # Get destination port
    encryption_key = bytes.fromhex(sys.argv[4])  # Convert encryption key from hex

    send_file(file_path, destination_ip, destination_port, encryption_key)
