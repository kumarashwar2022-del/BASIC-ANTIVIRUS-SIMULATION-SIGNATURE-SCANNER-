import os
import hashlib
import shutil
from datetime import datetime

# -------------------------------
# Calculate SHA256 Hash
# -------------------------------
def calculate_hash(file_path):
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            while True:
                data = file.read(4096)

                if not data:
                    break

                sha256.update(data)

        return sha256.hexdigest()

    except Exception as e:
        print(f"Error hashing {file_path}: {e}")
        return None


# -------------------------------
# Load Malware Signatures
# -------------------------------
def load_signatures():
    signatures = []

    try:
        with open("malware_signatures.txt", "r") as file:
            signatures = [line.strip() for line in file if line.strip()]

    except FileNotFoundError:
        print("malware_signatures.txt not found!")

    return signatures


# -------------------------------
# Log Events
# -------------------------------
def write_log(message):

    os.makedirs("reports", exist_ok=True)

    with open("reports/log.txt", "a") as log:
        log.write(f"{datetime.now()} - {message}\n")


# -------------------------------
# Quarantine File
# -------------------------------
def quarantine_file(file_path):

    os.makedirs("quarantine", exist_ok=True)

    destination = os.path.join(
        "quarantine",
        os.path.basename(file_path)
    )

    try:
        shutil.move(file_path, destination)
        return True

    except Exception as e:
        print(f"Quarantine Error: {e}")
        return False


# -------------------------------
# Scan Folder
# -------------------------------
def scan_folder(folder_path, signatures):

    total_files = 0
    infected_files = 0

    print("\n========== ANTIVIRUS SCAN STARTED ==========\n")

    for file in os.listdir(folder_path):

        path = os.path.join(folder_path, file)

        if os.path.isfile(path):

            total_files += 1

            file_hash = calculate_hash(path)

            if file_hash in signatures:

                infected_files += 1

                print(f"[ALERT] Malware Found : {file}")

                write_log(f"Malware Detected: {file}")

                if quarantine_file(path):
                    print("Moved To Quarantine Folder")

            else:
                print(f"[SAFE] {file}")

    return total_files, infected_files


# -------------------------------
# Generate Final Report
# -------------------------------
def generate_report(total_files, infected_files):

    os.makedirs("reports", exist_ok=True)

    with open("reports/report.txt", "w") as report:

        report.write("=====================================\n")
        report.write(" BASIC ANTIVIRUS SCAN REPORT\n")
        report.write("=====================================\n\n")

        report.write(
            f"Scan Date : {datetime.now()}\n"
        )

        report.write(
            f"Files Scanned : {total_files}\n"
        )

        report.write(
            f"Threats Found : {infected_files}\n"
        )

        report.write(
            f"Safe Files : {total_files - infected_files}\n"
        )

        if infected_files > 0:
            report.write(
                "\nStatus : THREATS DETECTED\n"
            )
        else:
            report.write(
                "\nStatus : SYSTEM CLEAN\n"
            )

    print("\nReport Saved -> reports/report.txt")


# -------------------------------
# Main Function
# -------------------------------
def main():

    sample_folder = "sample_files"

    if not os.path.exists(sample_folder):
        print("sample_files folder not found!")
        return

    signatures = load_signatures()

    total_files, infected_files = scan_folder(
        sample_folder,
        signatures
    )

    generate_report(
        total_files,
        infected_files
    )

    print("\n========== SCAN COMPLETED ==========")
    print(f"Files Scanned : {total_files}")
    print(f"Threats Found : {infected_files}")


if __name__ == "__main__":
    main()