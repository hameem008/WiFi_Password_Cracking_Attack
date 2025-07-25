#!/bin/bash

# Check interface state
iwconfig wlp3s0

# Revert monitor mode to managed mode
sudo ip link set wlp3s0 down
sudo iw dev wlp3s0 set type managed
sudo ip link set wlp3s0 up

# Restart NetworkManager to reconnect Wi-Fi
sudo systemctl restart NetworkManager

# Confirm back to managed mode
iwconfig wlp3s0

# Swithc to managed mode.