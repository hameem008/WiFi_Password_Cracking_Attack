# WiFi Password Cracking Attack Implementation

## 🎯 Project Overview
This project demonstrates a complete WPA2-PSK WiFi password cracking attack using dictionary-based and brute force methodologies, along with a comprehensive prevention system. The implementation follows ethical hacking principles and is designed for educational purposes.

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
5. **Attack Methods** (`attack_on_WiFi.py`)
   - **Dictionary Attack**: Test password candidates from dictionary
   - **Brute Force Attack**: Test all character combinations
   - **Comprehensive Attack**: Dictionary first, then brute force
   - Verify passwords using cryptographic verification

## 🔧 Technical Implementation

### Core Components

#### 1. WPA2Cracker Class (`WPA2Cracker.py`)
- **Handshake Extraction**: Parses EAPOL frames to extract ANonce, SNonce, and MIC
- **PTK Derivation**: Implements PBKDF2 and PRF for key generation
- **Password Verification**: Uses HMAC-SHA1 for MIC comparison
- **Dictionary Attack**: Systematic password testing with progress tracking
- **Brute Force Attack**: Tests all character combinations with configurable parameters

#### 2. Attack Orchestration (`attack_on_WiFi.py`)
- Configures attack parameters (capture file, SSID, dictionary)
- Provides interactive menu for attack method selection
- Manages attack flow and result reporting
- Supports customizable character sets and length ranges

#### 3. Network Tools
- **Monitor Mode**: `monitor_mode.sh` - Enables raw packet capture
- **Managed Mode**: `managed_mode.sh` - Restores normal WiFi operation
- **Packet Injection**: `packet_injection.sh` - Executes deauthentication attacks
- **Packet Capture**: `capture_packet.sh` - Captures handshake data

## 🛡️ Prevention System (`prevention.py`)

### Overview
The prevention system implements a comprehensive defense against WPA2 attacks using Object-Oriented Programming (OOP) principles. It encrypts ANonce and SNonce with router passwords to render captured handshake data useless.

### Core Classes

#### 1. SecureNonce Class
- **Encrypted Nonce Generation**: Uses PBKDF2 with 100,000 iterations
- **Replay Attack Prevention**: Maintains nonce history to detect reuse
- **Timestamp Validation**: 5-minute expiry for nonce freshness
- **Type Validation**: Distinguishes between ANonce and SNonce

#### 2. SecureHandshake Class
- **Encrypted 4-Way Handshake**: Protects entire authentication process
- **Session Management**: 60-second timeout with unique session IDs
- **Secure Key Generation**: Derives session keys from encrypted nonces
- **Step-by-Step Validation**: Ensures proper handshake progression

#### 3. Router Class (Main OOP Component)
- **Complete Router Simulation**: Full access point functionality
- **Brute Force Protection**: Client lockout after 5 failed attempts
- **Failed Attempt Tracking**: Per-client MAC address monitoring
- **Session Security**: Timeout management and activity tracking
- **Security Monitoring**: Real-time threat detection and response

#### 4. SecurityMonitor Class
- **Event Logging**: Comprehensive security event tracking
- **Alert System**: Real-time notifications for suspicious activity
- **Rate Limiting**: Detection of high-frequency attack patterns
- **Security Analytics**: Threat analysis and reporting

### Security Features

#### 🔐 Encrypted Nonces
- **ANonce/SNonce Encryption**: Uses router password with PBKDF2
- **Key Derivation**: 100,000 iterations for computational security
- **Timestamp Integration**: Prevents replay and timing attacks
- **Type Validation**: Ensures proper nonce usage

#### 🚫 Brute Force Protection
- **Client Lockout**: 5-minute ban after 5 failed attempts
- **Attempt Tracking**: Per-client MAC address monitoring
- **Automatic Reset**: Lockout expiration after timeout period
- **Progressive Delays**: Increasing delays for repeated failures

#### 🔄 Session Security
- **60-Second Timeout**: Prevents session hijacking
- **Unique Session IDs**: 16-byte random identifiers
- **Activity Tracking**: Monitors client behavior patterns
- **Secure Key Exchange**: Encrypted session key generation

#### 📊 Monitoring & Alerts
- **Real-Time Logging**: All security events recorded
- **Pattern Recognition**: Detects suspicious activity patterns
- **Rate Analysis**: Monitors authentication attempt frequency
- **Security Reporting**: Comprehensive status and threat reports

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

### Brute Force Attack Analysis
- **Character Sets**: Configurable (lowercase, uppercase, digits, symbols)
- **Length Ranges**: 1-8 characters (configurable)
- **Performance**: 1,000-50,000 passwords/second depending on hardware
- **Time Estimates**: 
  - 6 characters: ~25 days (at 1,000/sec)
  - 8 characters: ~92 years (at 1,000/sec)

## 🎯 Test Results

### Successful Attacks
| SSID | Password | Capture File | Attack Method | Status |
|------|----------|--------------|---------------|--------|
| ikeriri-5g | wireshark | ikeriri-5g.pcap | Dictionary | ✅ Cracked |
| BUETCSE | 1stCSE@BUET | BUETCSE.cap | Dictionary | ✅ Cracked |
| Ei j eta amar wifi | hehaheha | Ei j eta amar wifi.cap | Dictionary | ✅ Cracked |

### Prevention System Effectiveness
- **Encrypted Nonces**: Renders captured handshake data useless
- **Brute Force Protection**: Prevents systematic password attacks
- **Session Security**: Eliminates session hijacking vulnerabilities
- **Real-Time Monitoring**: Detects and responds to threats immediately

## 🚀 Usage Instructions

### Prerequisites
```bash
# Install required tools
sudo apt-get install aircrack-ng wireshark python3-scapy

# Install Python dependencies
pip install -r requirements.txt
```

### Attack Execution
```bash
# 1. Enable monitor mode
./monitor_mode.sh

# 2. Discover networks and capture handshake
./capture_packet.sh

# 3. Execute attack (interactive menu)
python3 attack_on_WiFi.py

# 4. Restore managed mode
./managed_mode.sh
```

### Prevention System Testing
```bash
# Run prevention system demonstration
python3 prevention.py
```

## 🔒 Security Implications

### Attack Vectors
- **Deauthentication**: Forces client re-authentication
- **Dictionary Attack**: Tests common password patterns
- **Brute Force Attack**: Tests all character combinations
- **Handshake Capture**: Exploits WPA2 protocol weaknesses

### Countermeasures (Prevention System)
- **Encrypted Nonces**: Makes captured data useless without encryption key
- **Brute Force Protection**: Client lockout prevents systematic attacks
- **Session Security**: Timeouts and validation prevent hijacking
- **Real-Time Monitoring**: Immediate threat detection and response
- **Replay Protection**: Nonce history prevents replay attacks

### Traditional Countermeasures
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
- Understanding attack vectors and prevention methods

**NEVER use this tool against networks you don't own or have explicit permission to test.**

## 🛠️ Technical Requirements

### Attack Tools
- Linux environment with wireless capabilities
- Compatible wireless adapter with monitor mode support
- Root/administrator privileges
- Python 3.x with required libraries
- Aircrack-ng suite

### Prevention System
- Python 3.x
- cryptography library
- scapy library
- pbkdf2 library

## 📚 References

- IEEE 802.11i Standard
- WPA2 Security Protocol
- PBKDF2 Key Derivation (RFC 2898)
- HMAC-SHA1 Implementation
- EAPOL Frame Structure
- Cryptographic Nonce Security
- Session Management Best Practices

---

**Author**: [Your Name]  
**Course**: [Course Name]  
**Institution**: [Institution Name]  
**Date**: [Date]