import struct
import re

MAGIC_HEADER = b"RP"

# Encoder function for OP_RETURN reports
def encode_op_return(reports: list) -> bytes:
    encoded_reports = b""
    for report_type, message_bytes, hashtags, extra in reports:
        hashtags_str = ",".join(hashtags)
        hashtags_bytes = hashtags_str.encode("utf-8")
        message_length = len(message_bytes)
        hashtags_length = len(hashtags_bytes)
        header = struct.pack(">2sBBH", MAGIC_HEADER, 1, report_type, message_length)
        encoded_reports += header + message_bytes + struct.pack(">H", hashtags_length) + hashtags_bytes
        if report_type == 11 and extra is not None:
            # Append 32-byte txid for revocation
            encoded_reports += extra
    return encoded_reports
def decode_op_return(data: bytes):
    report_types = {
        1: "Positive",
        2: "Negative",
        3: "Name",
        4: "Other",
        5: "Neutral",
        6: "Spam",
        7: "Fraud",
        8: "Complaint",
        9: "Praise",
        10: "Warning",
        11: "Revocation"
    }
    offset = 0
    report_num = 1
    first_version = None

    while offset < len(data):
        if len(data) - offset < 6:
            print("Incomplete data for header")
            break
        magic, version, report_type, msg_len = struct.unpack(">2sBBH", data[offset:offset+6])
        if first_version is None:
            first_version = version
            print(f"Version: {version}")
        elif version != first_version:
            print(f"Warning: report #{report_num} has different version: {version}")
        # else: (version matches and not first report), do not print version
        if magic != MAGIC_HEADER:
            print("Invalid report")
            return
        if version != 1:
            print(f"Unsupported version: {version}")
            return
        offset += 6

        if len(data) - offset < msg_len + 2:
            print("Incomplete data for message and hashtags")
            break

        message = data[offset:offset+msg_len].decode("utf-8", errors="replace")
        offset += msg_len

        hashtags_len = struct.unpack(">H", data[offset:offset+2])[0]
        offset += 2

        if len(data) - offset < hashtags_len:
            print("Incomplete hashtags data")
            break

        hashtags = data[offset:offset+hashtags_len].decode("utf-8", errors="replace")
        offset += hashtags_len

        report_type_str = report_types.get(report_type, f"Unknown ({report_type})")

        if report_type in report_types:
            print(f"\n{report_num}) {report_type_str}")
        else:
            print(f"\n{report_num}) {report_type}")
        print(f"Message: {message}")
        print(f"Hashtags: {hashtags}")

        if report_type == 11:
            if len(data) - offset < 32:
                print("Incomplete revocation txid data")
                break
            txid_bytes = data[offset:offset+32]
            offset += 32
            print(f"Revoked TXID: {txid_bytes.hex()}")

        report_num += 1


# Add main() and entry point guard
def prompt_report_type() -> int:
    predefined = {
        1: "Positive",
        2: "Negative",
        3: "Name",
        4: "Other",
        5: "Neutral",
        6: "Spam",
        7: "Fraud",
        8: "Complaint",
        9: "Praise",
        10: "Warning",
        11: "Revocation"
    }

    print("Report type (1-11):")
    for k in range(1, 12):
        print(f"{k}) {predefined[k]}")
    while True:
        choice = input("Enter number (1-255). Above 11 is undefined here: ").strip()
        try:
            num = int(choice)
            if 1 <= num <= 255:
                return num
        except:
            pass
        print("Invalid number.")

def prompt_message() -> bytes:
    msg = input("Message (optional): ").strip()
    return msg.encode("utf-8")

def prompt_hashtags() -> list:
    tags = input("Hashtags (comma-separated): ").strip()
    if not tags:
        return []
    return [tag.strip() for tag in tags.split(",")]

def prompt_txid() -> str or None:
    pattern = re.compile(r"^[0-9a-f]{64}$")
    while True:
        txid = input("Enter TXID (64 lowercase hex chars): ").strip()
        if pattern.match(txid):
            return txid
        print("Invalid TXID.")
        print("1) Retry entering txid")
        print("2) Back")
        choice = input("Enter choice (1-2): ").strip()
        if choice == "2":
            return None

def print_single_report(report_tuple, report_number):
    # report_tuple is (report_type, message_bytes, hashtags, extra)
    encoded = encode_op_return([report_tuple])
    print(f"\nCurrent Report {report_number}:")
    decode_op_return(encoded)

def main():
    print("OP_RETURN Reputation Encoder/Decoder")
    mode = ""
    while mode not in ("e", "d"):
        mode = input("Mode (e=encode, d=decode): ").strip().lower()
    if mode == "e":
        reports = []
        while True:
            report_type = prompt_report_type()
            if report_type == 11:
                txid = prompt_txid()
                if txid is None:
                    continue  # skip adding revocation report, go back to report selection
                message_bytes = prompt_message()
                hashtags = prompt_hashtags()
                extra = bytes.fromhex(txid)
                reports.append((report_type, message_bytes, hashtags, extra))
                print_single_report(reports[-1], len(reports))
                print("\n" + "-" * 40 + "\n")
            else:
                message_bytes = prompt_message()
                hashtags = prompt_hashtags()
                extra = None
                reports.append((report_type, message_bytes, hashtags, extra))
                print_single_report(reports[-1], len(reports))
                print("\n" + "-" * 40 + "\n")
            while True:
                print("1) Redo this report")
                print("2) Proceed to next report")
                print("3) Finish all reports")
                choice = input("Enter choice (1-3): ").strip()
                if choice == "1":
                    # Redo this report: pop last and re-enter
                    reports.pop()
                    report_type = prompt_report_type()
                    if report_type == 11:
                        txid = prompt_txid()
                        if txid is None:
                            break  # back to report selection menu
                        message_bytes = prompt_message()
                        hashtags = prompt_hashtags()
                        extra = bytes.fromhex(txid)
                        reports.append((report_type, message_bytes, hashtags, extra))
                        print_single_report(reports[-1], len(reports))
                        print("\n" + "-" * 40 + "\n")
                    else:
                        message_bytes = prompt_message()
                        hashtags = prompt_hashtags()
                        extra = None
                        reports.append((report_type, message_bytes, hashtags, extra))
                        print_single_report(reports[-1], len(reports))
                        print("\n" + "-" * 40 + "\n")
                    continue  # Show menu again after redoing
                elif choice == "2":
                    # Proceed to next report
                    break  # Break inner menu loop, outer loop adds new report
                elif choice == "3":
                    # Finish all reports
                    break  # Break inner menu loop
                else:
                    print("Invalid choice. Please enter 1, 2, or 3.")
            if choice == "3":
                break
        encoded = encode_op_return(reports)
        print("\nEncoded data (hex):")
        print(encoded.hex())
        print("\nDecoded reports:")
        decode_op_return(encoded)
    else:
        hex_data = input("Enter OP_RETURN data as hex string: ").strip()
        try:
            data_bytes = bytes.fromhex(hex_data)
        except ValueError:
            print("Invalid hex input.")
            return
        decode_op_return(data_bytes)

if __name__ == "__main__":
    main()