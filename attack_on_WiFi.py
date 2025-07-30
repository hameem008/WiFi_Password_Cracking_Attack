from WPA2Cracker import *
import string


def main():
    """
    MAIN EXECUTION FLOW:
    1. Parse capture file to extract 4-way handshake
    2. Read dictionary file with candidate passwords
    3. Perform dictionary attack to crack WPA2 password
    4. Optionally perform brute force attack
    """

    # Configuration
    capture_file = "Ei j eta amar wifi.cap"
    ssid = "Ei j eta amar wifi"
    dictionary_file = "dictionary.txt"

    # Initialize cracker and extract handshake
    cracker = WPA2Cracker(capture_file, ssid)
    print("🔍 Extracting handshake...")

    if not cracker.extract_handshake():
        print("❌ Handshake extraction failed")
        return

    print("\n" + "="*50)
    print("🔓 WPA2 PASSWORD CRACKING TOOL")
    print("="*50)
    
    # Ask user for attack method
    print("\nSelect attack method:")
    print("1. Dictionary Attack")
    print("2. Brute Force Attack")
    print("3. All Methods (dictionary first, then brute force)")
    
    try:
        choice = input("\nEnter your choice (1-3): ").strip()
    except KeyboardInterrupt:
        print("\n\n❌ Attack cancelled by user")
        return

    result = None

    if choice == "1":
        # Dictionary Attack
        print("\n⚡ Starting dictionary attack...")
        result = cracker.dictionary_attack(dictionary_file)

    elif choice == "2":
        # Brute Force Attack
        print("\n🔨 Starting brute force attack...")
        
        # Get user preferences for brute force
        try:
            max_len = int(input("Enter maximum password length (default: 6): ") or "6")
            use_uppercase = input("Include uppercase letters? (y/n, default: n): ").lower().startswith('y')
            use_symbols = input("Include symbols? (y/n, default: n): ").lower().startswith('y')
        except (ValueError, KeyboardInterrupt):
            print("Using default settings...")
            max_len = 6
            use_uppercase = False
            use_symbols = False

        # Build character set
        charset = string.ascii_lowercase + string.digits
        if use_uppercase:
            charset += string.ascii_uppercase
        if use_symbols:
            charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"

        result = cracker.brute_force_attack(
            charset=charset,
            min_length=1,
            max_length=max_len
        )

    elif choice == "3":
        # All Methods
        print("\n🚀 Starting comprehensive attack...")
        
        # Step 1: Dictionary Attack
        print("\n📚 Step 1: Dictionary Attack")
        result = cracker.dictionary_attack(dictionary_file)
        
        if not result:
            print("\n📚 Dictionary attack failed, trying brute force...")
            
            # Step 2: Brute Force Attack
            print("\n🔨 Step 2: Brute Force Attack")
            result = cracker.brute_force_attack(
                charset=string.ascii_lowercase + string.digits,
                min_length=1,
                max_length=6
            )

    else:
        print("❌ Invalid choice. Please run the script again.")
        return

    # Display results
    print("\n" + "="*50)
    if result:
        print(f"🎯 SUCCESS! Cracked password: {result}")
        print(f"📶 SSID: {ssid}")
        print(f"🔑 Password: {result}")
    else:
        print("💥 Attack failed - password not found")
        print("💡 Try increasing the dictionary size or brute force length")
    print("="*50)


if __name__ == "__main__":
    main()