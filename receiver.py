import socket  # Import socket module for network communication
import hashlib  # Import hashlib for computing checksums
import sys  # Import sys for command-line argument handling
from Crypto.Cipher import AES  # Import AES for decryption
from Crypto.Util.Padding import unpad  # Import unpad utility for AES decryption
import time  # Import time for delays and performance measurement


def calculate_checksum(data):
    """Calculate SHA-256 checksum of given data."""
    return hashlib.sha256(data).digest()


def decrypt_data(encrypted_data, key):
    """Decrypt data using AES CBC mode."""
    iv = encrypted_data[:AES.block_size]  # Extract IV from the encrypted data
    ct = encrypted_data[AES.block_size:]  # Extract actual encrypted content
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Create AES cipher with given key
    return unpad(cipher.decrypt(ct), AES.block_size)  # Decrypt and remove padding


def receive_file(output_file, listen_port, decryption_key):
    """Receive an encrypted file over a TCP socket and decrypt it."""
    collected_data = {}  # Dictionary to store received packets
    total_packets = None  # Total expected packets
    missing_packets = set()  # Track missing packets for retransmission

    # Create a TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow port reuse
    sock.bind(("0.0.0.0", listen_port))  # Bind to all available interfaces
    sock.listen(1)  # Listen for incoming connections

    print(f"📡 Receiver listening on port {listen_port}...")

    conn, addr = sock.accept()  # Accept incoming connection
    print(f"✅ Connected to sender at {addr}")

    start_time = None  # Variable to store the start time for performance tracking

    try:
        # Receive the header containing the total packet count
        header = b""
        while True:
            chunk = conn.recv(1)  # Read one byte at a time to detect header end
            if not chunk:
                break
            header += chunk
            if header.endswith(b"\n"):
                break

        print(f"💚 Received raw header: {header.decode(errors='ignore').strip()}")

        # Validate and extract total packet count
        try:
            if not header.startswith(b"HEAD:"):
                raise ValueError("Invalid header format")

            header_parts = header.decode(errors='ignore').strip().split(":", 1)
            if len(header_parts) != 2:
                raise ValueError("Malformed header structure")

            total_packets_str = header_parts[1].strip()
            if not total_packets_str.isdigit():
                raise ValueError(f"Packet count is not a number: {total_packets_str}")

            total_packets = int(total_packets_str)
            if total_packets <= 0 or total_packets > 10000:
                raise ValueError(f"Unreasonable packet count: {total_packets}")

            missing_packets = set(range(total_packets))  # Initialize missing packets
            print(f"📚 Received header: {total_packets} packets expected.")
            start_time = time.time()

        except ValueError as e:
            print(f"❌ Error: Malformed header received ({e}). Aborting.")
            conn.close()
            return

        # Process received packets
        while True:
            try:
                payload = conn.recv(8192)  # Receive up to 8192 bytes
                if not payload:
                    break

                # Split the payload into sequence number and data
                parts = payload.split(b':', 1)
                if len(parts) < 2:
                    print("⚠️ Warning: Received malformed packet, ignoring.")
                    continue

                seq_str = parts[0].decode(errors='ignore').strip()
                if seq_str.isdigit():
                    seq_num = int(seq_str)  # Convert sequence number to integer
                    encrypted_chunk_data = parts[1][:-32]  # Extract encrypted data
                    received_checksum = parts[1][-32:]  # Extract checksum

                    # Verify checksum
                    calculated_checksum = calculate_checksum(encrypted_chunk_data)
                    if calculated_checksum == received_checksum:
                        decrypted_chunk_data = decrypt_data(encrypted_chunk_data, decryption_key)
                        if seq_num not in collected_data:
                            collected_data[seq_num] = decrypted_chunk_data
                            missing_packets.discard(seq_num)  # Remove from missing list
                            print(f"✅ Packet {seq_num} received and validated.")
                    else:
                        print(f"❌ Checksum mismatch for packet {seq_num}, requesting retransmission.")
                        missing_packets.add(seq_num)

                # Check if all packets have been received
                if total_packets is not None and not missing_packets:
                    print("💾 All packets received. Writing to file...")
                    with open(output_file, 'wb') as f:
                        for i in range(total_packets):
                            if i in collected_data:
                                f.write(collected_data[i])
                            else:
                                print(f"⚠️ Warning: Packet {i} missing from collected data.")

                    print(f"✅ File successfully written to {output_file}")
                    elapsed_time = time.time() - start_time
                    print(f"⏳ Total time taken: {elapsed_time:.2f} seconds")

                    conn.sendall(b"ACK")  # Send acknowledgment
                    time.sleep(3)
                    break

                # Request retransmission of missing packets
                elif missing_packets:
                    valid_missing_packets = sorted([seq for seq in missing_packets if seq < total_packets])
                    if valid_missing_packets:
                        missing_list = ",".join(str(seq) for seq in valid_missing_packets).encode()
                        conn.sendall(missing_list)
                        print(f"🔄 Requesting retransmission for packets: {missing_list.decode()}")

            except Exception as e:
                print(f"❌ Error processing packet: {e}")
                continue

    finally:
        conn.close()  # Close connection
        sock.close()  # Close socket


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python receiver.py <output_file> <listen_port> <decryption_key>")
        sys.exit(1)

    output_file = sys.argv[1]  # Get output file path
    listen_port = int(sys.argv[2])  # Get listening port
    decryption_key = bytes.fromhex(sys.argv[3])  # Convert decryption key from hex

    receive_file(output_file, listen_port, decryption_key)
