import struct
import re

# 
# ANSI color codes for report types and UI elements (fully saturated, evenly spaced bright colors for CLI output)
# COLOR_CODES_BY_TYPE maps report type numbers to bright, fully saturated ANSI escape codes.
COLOR_CODES_BY_TYPE = {
    1: "\033[1;32m",   # Positive - Bright Green
    2: "\033[1;31m",   # Negative - Bright Red
    3: "\033[1;34m",   # Name - Bright Blue
    4: "\033[1;97m",   # Other - Bright White
    5: "\033[1;37m",   # Neutral - White
    6: "\033[1;35m",   # Spam - Bright Magenta
    7: "\033[1;33m",   # Fraud - Bright Yellow
    8: "\033[1;36m",   # Complaint - Bright Cyan
    9: "\033[1;34m",   # Praise - Bright Blue
    10: "\033[1;32m",  # Warning - Bright Green
    11: "\033[1;97m",  # Revocation - Bright White
}
# ANSI escape code to reset color
RESET = "\033[0m"

# COLOR_MAP is a modular color map for all CLI UI elements and report types.
# It merges COLOR_CODES_BY_TYPE and adds entries for UI prompts, errors, etc.
COLOR_MAP = {
    **COLOR_CODES_BY_TYPE,
    "encoded_data_label": "\033[1;33m",  # Bitcoin yellow/gold bright yellow
    "menu_prompt": "\033[1;36m",         # Bright cyan for prompts
    "error_message": "\033[1;31m",       # Bright red for errors
}

def color_text(text, report_type, color_map):
    """
    Wraps the given text in ANSI color codes based on report type using a provided color map.
    This function allows modular color usage by accepting a color_map parameter,
    enabling different color schemes or overrides to be passed in as needed.
    """
    color = color_map.get(report_type, RESET)
    return f"{color}{text}{RESET}"

# Modular helper for printing colored text based on COLOR_MAP and key.
# If color_key is provided and found in COLOR_MAP, prints colored text; otherwise prints plain.
def colored_print(text, color_key=None):
    """
    Print the given text with color based on the UI element or report type.
    Looks up color code in COLOR_MAP by color_key.
    If color_key is not found, prints plain text.
    """
    color = COLOR_MAP.get(color_key, None)
    if color is not None:
        print(f"{color}{text}{RESET}")
    else:
        print(text)

MAGIC_HEADER = b"RP"

REPORT_CONFIG = {
    1: {
        "name": "Positive",
        "fields": {
            "message": "Message (optional)",
            "hashtags": "Hashtags (comma-separated)"
        }
    },
    2: {
        "name": "Negative",
        "fields": {
            "message": "Message (optional)",
            "hashtags": "Hashtags (comma-separated)"
        }
    },
    3: {
        "name": "Name",
        "fields": {
            "hashtags": "Names (comma-separated)",
            "message": "Commentary (optional)"
        }
    },
    4: {
        "name": "Other",
        "fields": {
            "message": "Message (optional)",
            "hashtags": "Hashtags (comma-separated)"
        }
    },
    5: {
        "name": "Neutral",
        "fields": {
            "message": "Message (optional)",
            "hashtags": "Hashtags (comma-separated)"
        }
    },
    6: {
        "name": "Spam",
        "fields": {
            "message": "Message (optional)",
            "hashtags": "Hashtags (comma-separated)"
        }
    },
    7: {
        "name": "Fraud",
        "fields": {
            "message": "Message (optional)",
            "hashtags": "Hashtags (comma-separated)"
        }
    },
    8: {
        "name": "Complaint",
        "fields": {
            "message": "Message (optional)",
            "hashtags": "Hashtags (comma-separated)"
        }
    },
    9: {
        "name": "Praise",
        "fields": {
            "message": "Message (optional)",
            "hashtags": "Hashtags (comma-separated)"
        }
    },
    10: {
        "name": "Warning",
        "fields": {
            "message": "Message (optional)",
            "hashtags": "Hashtags (comma-separated)"
        }
    },
    11: {
        "name": "Revocation",
        "fields": {
            "hashtags": "Hashtags (comma-separated)",
            "message": "Message (optional)",
            "extra": "TXID (64 hex chars)"
        }
    },
    "default": {
        "name": "Unknown",
        "fields": {
            "message": "Message (optional)",
            "hashtags": "Hashtags (comma-separated)"
        }
    }
}

def get_report_config(report_type):
    return REPORT_CONFIG.get(report_type, REPORT_CONFIG["default"])

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
    offset = 0
    report_num = 1
    first_version = None
    reports = []

    while offset < len(data):
        if len(data) - offset < 6:
            # Incomplete data for header
            break
        magic, version, report_type, msg_len = struct.unpack(">2sBBH", data[offset:offset+6])
        if magic != MAGIC_HEADER:
            # Invalid report
            break
        if version != 1:
            # Unsupported version
            break
        if first_version is None:
            first_version = version
        version_warning = (version != first_version)
        offset += 6

        if len(data) - offset < msg_len + 2:
            # Incomplete data for message and hashtags
            break

        message = data[offset:offset+msg_len].decode("utf-8", errors="replace")
        offset += msg_len

        hashtags_len = struct.unpack(">H", data[offset:offset+2])[0]
        offset += 2

        if len(data) - offset < hashtags_len:
            # Incomplete hashtags data
            break

        hashtags = data[offset:offset+hashtags_len].decode("utf-8", errors="replace")
        offset += hashtags_len

        revoked_txid = None
        if report_type == 11:
            if len(data) - offset < 32:
                # Incomplete revocation txid data
                break
            txid_bytes = data[offset:offset+32]
            offset += 32
            revoked_txid = txid_bytes.hex()

        report_config = get_report_config(report_type)
        report_name = report_config["name"]

        report_dict = {
            "report_num": report_num,
            "report_type": report_type,
            "report_name": report_name,
            "message": message,
            "hashtags": hashtags,
            "revoked_txid": revoked_txid,
            "version_warning": version_warning
        }
        reports.append(report_dict)
        report_num += 1

    return reports

def render_cli_reports(reports: list, color_map=None):
    """
    Render decoded reports to the CLI with optional color coding.
    Uses colored_print for colored output.
    """
    if color_map is None:
        color_map = {}
    if not reports:
        colored_print("No valid reports decoded.", "error_message")
        return
    first_version_printed = False
    for report in reports:
        if not first_version_printed:
            colored_print(f"Version: 1", "menu_prompt")
            first_version_printed = True
        elif report["version_warning"]:
            # Color the warning in bright yellow for visibility
            colored_print(color_text(f"Warning: report #{report['report_num']} has different version: 1", 10, color_map))
        # Color the report header (number and name) based on report type
        header = f"\n{report['report_num']}) {report['report_name']}"
        colored_print(color_text(header, report["report_type"], color_map))
        fields = get_report_config(report["report_type"])["fields"]
        hashtag_label = fields.get("hashtags", "Hashtags (comma-separated)").replace("(comma-separated)", "").strip(": ")
        message_label = fields.get("message", "Message (optional)").replace("(optional)", "").strip(": ")
        colored_print(f"{hashtag_label}: {report['hashtags']}")
        colored_print(f"{message_label}: {report['message']}")
        if report["report_type"] == 11 and report["revoked_txid"] is not None:
            # Color the revoked TXID in bright gray
            colored_print(color_text(f"Revoked TXID: {report['revoked_txid']}", 11, color_map))

# Add main() and entry point guard
def prompt_report_type() -> int:
    predefined = {k: v["name"] for k, v in REPORT_CONFIG.items() if isinstance(k, int)}

    colored_print("Report type (1-11):", "menu_prompt")
    for k in range(1, 12):
        colored_print(f"{k}) {predefined[k]}", k)
    while True:
        choice = input("Enter number (1-255). Above 11 is undefined here: ").strip()
        try:
            num = int(choice)
            if 1 <= num <= 255:
                return num
        except:
            pass
        colored_print("Invalid number.", "error_message")

def prompt_message() -> bytes:
    msg = input("Message (optional): ").strip()
    return msg.encode("utf-8")

def prompt_hashtags(prompt_text="Names (comma-separated): ") -> list:
    tags = input(prompt_text).strip()
    if not tags:
        return []
    return [tag.strip() for tag in tags.split(",")]

def prompt_txid() -> str or None:
    pattern = re.compile(r"^[0-9a-f]{64}$")
    while True:
        txid = input("Enter TXID (64 lowercase hex chars): ").strip()
        if pattern.match(txid):
            return txid
        colored_print("Invalid TXID.", "error_message")
        colored_print("1) Retry entering txid", "menu_prompt")
        colored_print("2) Back", "menu_prompt")
        choice = input("Enter choice (1-2): ").strip()
        if choice == "2":
            return None

def print_single_report(report_tuple, report_number):
    # report_tuple is (report_type, message_bytes, hashtags, extra)
    encoded = encode_op_return([report_tuple])
    colored_print(f"\nCurrent Report {report_number}:", "menu_prompt")
    decode_reports = decode_op_return(encoded)
    render_cli_reports(decode_reports, color_map=COLOR_CODES_BY_TYPE)

def main():
    colored_print("OP_RETURN Reputation Encoder/Decoder", "menu_prompt")
    mode = ""
    while mode not in ("e", "d"):
        mode = input("Mode (e=encode, d=decode): ").strip().lower()
    if mode == "e":
        reports = []
        while True:
            report_type = prompt_report_type()
            report_config = get_report_config(report_type)
            fields = report_config["fields"]
            if report_type == 11:
                hashtags = prompt_hashtags(fields.get("hashtags", "") + ": ")
                message_bytes = input(fields.get("message", "") + ": ").strip().encode("utf-8")
                txid = prompt_txid()
                if txid is None:
                    continue  # skip adding revocation report, go back to report selection
                extra = bytes.fromhex(txid)
                reports.append((report_type, message_bytes, hashtags, extra))
                print_single_report(reports[-1], len(reports))
                colored_print("\n" + "-" * 40 + "\n", "menu_prompt")
            elif report_type == 3:
                hashtags = prompt_hashtags(fields.get("hashtags", "") + ": ")
                message_bytes = input(fields.get("message", "") + ": ").strip().encode("utf-8")
                extra = None
                reports.append((report_type, message_bytes, hashtags, extra))
                print_single_report(reports[-1], len(reports))
                colored_print("\n" + "-" * 40 + "\n", "menu_prompt")
            else:
                message_bytes = input(fields.get("message", "") + ": ").strip().encode("utf-8")
                hashtags = prompt_hashtags(fields.get("hashtags", "") + ": ")
                extra = None
                reports.append((report_type, message_bytes, hashtags, extra))
                print_single_report(reports[-1], len(reports))
                colored_print("\n" + "-" * 40 + "\n", "menu_prompt")
            while True:
                # Print menu in new order:
                colored_print("1) Redo this report", "menu_prompt")
                colored_print("2) Proceed to next report", "menu_prompt")
                colored_print("4) Delete previous report", "menu_prompt")
                colored_print("3) Finish all reports", "menu_prompt")
                choice = input("Enter choice (1-4): ").strip()
                if not choice:
                    # Empty input is treated as "3" (Finish all reports)
                    choice = "3"
                if choice == "1":
                    # Redo this report: pop last and re-enter
                    reports.pop()
                    report_type = prompt_report_type()
                    report_config = get_report_config(report_type)
                    fields = report_config["fields"]
                    if report_type == 11:
                        hashtags = prompt_hashtags(fields.get("hashtags", "") + ": ")
                        message_bytes = input(fields.get("message", "") + ": ").strip().encode("utf-8")
                        txid = prompt_txid()
                        if txid is None:
                            break  # back to report selection menu
                        extra = bytes.fromhex(txid)
                        reports.append((report_type, message_bytes, hashtags, extra))
                        print_single_report(reports[-1], len(reports))
                        colored_print("\n" + "-" * 40 + "\n", "menu_prompt")
                    elif report_type == 3:
                        hashtags = prompt_hashtags(fields.get("hashtags", "") + ": ")
                        message_bytes = input(fields.get("message", "") + ": ").strip().encode("utf-8")
                        extra = None
                        reports.append((report_type, message_bytes, hashtags, extra))
                        print_single_report(reports[-1], len(reports))
                        colored_print("\n" + "-" * 40 + "\n", "menu_prompt")
                    else:
                        message_bytes = input(fields.get("message", "") + ": ").strip().encode("utf-8")
                        hashtags = prompt_hashtags(fields.get("hashtags", "") + ": ")
                        extra = None
                        reports.append((report_type, message_bytes, hashtags, extra))
                        print_single_report(reports[-1], len(reports))
                        colored_print("\n" + "-" * 40 + "\n", "menu_prompt")
                    continue  # Show menu again after redoing
                elif choice == "2":
                    # Proceed to next report
                    break  # Break inner menu loop, outer loop adds new report
                elif choice == "4":
                    if reports:
                        reports.pop()
                        colored_print("Previous report deleted.", "menu_prompt")
                        if not reports:
                            colored_print("No reports left. Returning to main menu...", "error_message")
                            return
                    else:
                        colored_print("No reports to delete.", "error_message")
                    continue
                elif choice == "3":
                    # Finish all reports
                    break  # Break inner menu loop
                else:
                    colored_print("Invalid choice. Please enter 1, 2, 3, or 4.", "error_message")
            if choice == "3":
                break
        colored_print("\nEncoded data (hex):", "encoded_data_label")
        colored_print(encode_op_return(reports).hex(), "encoded_data_label")
        colored_print("\nDecoded reports:", "menu_prompt")
        decoded_reports = decode_op_return(encode_op_return(reports))
        render_cli_reports(decoded_reports, color_map=COLOR_CODES_BY_TYPE)
    else:
        hex_data = input("Enter OP_RETURN data as hex string: ").strip()
        try:
            data_bytes = bytes.fromhex(hex_data)
        except ValueError:
            colored_print("Invalid hex input.", "error_message")
            return
        decoded_reports = decode_op_return(data_bytes)
        render_cli_reports(decoded_reports, color_map=COLOR_CODES_BY_TYPE)

if __name__ == "__main__":
    main()