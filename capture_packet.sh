./packet_injection.sh
sudo airodump-ng wlp3s0 # Checking for MAC of AP
sudo airodump-ng --bssid 8E:FA:5F:79:06:05 --channel 6 --write handshake wlp3s0 # Capturing packet
# sudo airodump-ng --bssid 8E:FA:5F:79:06:05 --channel 6 wlp3s0 # Checking the list who is connected
