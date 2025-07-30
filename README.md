# WiFi Password Cracking Attack Implementation

## 🎯 Project Overview
This project demonstrates a complete WPA2-PSK WiFi password cracking attack using dictionary-based methodology. The implementation follows ethical hacking principles and is designed for educational purposes.

## 🏗️ Architecture & Attack Flow

### Phase 1: Network Reconnaissance
1. **Switch to Monitor Mode** (`monitor_mode.sh`)
   - Disable conflicting services
   - Configure wireless interface for packet capture
   - Enable monitor mode for raw packet access

2. **Network Discovery** (`capture_packet.sh`)
   - Scan for available WiFi networks
   - Identify target Access Point (AP) and connected clients
   - Determine BSSID, channel, and client MAC addresses

### Phase 2: Handshake Capture
3. **Deauthentication Attack** (`packet_injection.sh`)
   - Force client disconnection using deauth packets
   - Trigger 4-way handshake re-authentication
   - Target specific client or broadcast to all clients

4. **Handshake Capture** (`capture_packet.sh`)
   - Monitor and capture EAPOL frames
   - Extract complete 4-way handshake
   - Save to `.cap` or `.pcap` file format

### Phase 3: Password Cracking
5. **Dictionary Attack** (`attack_on_WiFi.py`)
   - Parse captured handshake data
   - Test password candidates from dictionary
   - Verify passwords using cryptographic verification

## 🔧 Technical Implementation

### Core Components

#### 1. WPA2Cracker Class (`WPA2Cracker.py`)
- **Handshake Extraction**: Parses EAPOL frames to extract ANonce, SNonce, and MIC
- **PTK Derivation**: Implements PBKDF2 and PRF for key generation
- **Password Verification**: Uses HMAC-SHA1 for MIC comparison
- **Dictionary Attack**: Systematic password testing with progress tracking

#### 2. Attack Orchestration (`attack_on_WiFi.py`)
- Configures attack parameters (capture file, SSID, dictionary)
- Manages attack flow and result reporting
- Provides user-friendly output and error handling

#### 3. Network Tools
- **Monitor Mode**: `monitor_mode.sh` - Enables raw packet capture
- **Managed Mode**: `managed_mode.sh` - Restores normal WiFi operation
- **Packet Injection**: `packet_injection.sh` - Executes deauthentication attacks
- **Packet Capture**: `capture_packet.sh` - Captures handshake data

## 📊 Attack Methodology

### WPA2 4-Way Handshake Process
1. **Message 1**: AP → Client (ANonce)
2. **Message 2**: Client → AP (SNonce + MIC)
3. **Message 3**: AP → Client (GTK + MIC)
4. **Message 4**: Client → AP (ACK)

### Cryptographic Verification
- **PMK**: Derived using PBKDF2(passphrase, SSID, 4096 iterations)
- **PTK**: Generated using PRF(PMK, "Pairwise key expansion", MACs||Nonces)
- **MIC**: HMAC-SHA1(KCK, EAPOL_frame_with_zeroed_MIC)

## 🎯 Test Results

### Successful Attacks
| SSID | Password | Capture File | Status |
|------|----------|--------------|--------|
| ikeriri-5g | wireshark | ikeriri-5g.pcap | ✅ Cracked |
| BUETCSE | 1stCSE@BUET | BUETCSE.cap | ✅ Cracked |
| Ei j eta amar wifi | hehaheha | Ei j eta amar wifi.cap | ✅ Cracked |

## 🚀 Usage Instructions

### Prerequisites
```bash
# Install required tools
sudo apt-get install aircrack-ng wireshark python3-scapy

# Install Python dependencies
pip install pbkdf2
```

### Attack Execution
```bash
# 1. Enable monitor mode
./monitor_mode.sh

# 2. Discover networks and capture handshake
./capture_packet.sh

# 3. Execute dictionary attack
python3 attack_on_WiFi.py

# 4. Restore managed mode
./managed_mode.sh
```

## 🔒 Security Implications

### Attack Vectors
- **Deauthentication**: Forces client re-authentication
- **Dictionary Attack**: Tests common password patterns
- **Handshake Capture**: Exploits WPA2 protocol weaknesses

### Countermeasures
- Use strong, unique passwords
- Implement WPA3 when possible
- Monitor for deauthentication attacks
- Use enterprise authentication (802.1X)

## 📝 Ethical Considerations

⚠️ **IMPORTANT**: This tool is designed for:
- Educational purposes
- Security research
- Penetration testing with proper authorization
- Network security assessment

**NEVER use this tool against networks you don't own or have explicit permission to test.**

## 🛠️ Technical Requirements

- Linux environment with wireless capabilities
- Compatible wireless adapter with monitor mode support
- Root/administrator privileges
- Python 3.x with required libraries
- Aircrack-ng suite

## 📚 References

- IEEE 802.11i Standard
- WPA2 Security Protocol
- PBKDF2 Key Derivation (RFC 2898)
- HMAC-SHA1 Implementation
- EAPOL Frame Structure

---

**Author**: [Your Name]  
**Course**: [Course Name]  
**Institution**: [Institution Name]  
**Date**: [Date]