#!/bin/bash

# Check interface status
iwconfig wlp3s0

# Kill conflicting services (important for monitor mode tools)
sudo airmon-ng check kill

# Enable monitor mode (manual, no virtual interface like wlp3s0mon)
sudo ip link set wlp3s0 down
sudo iw dev wlp3s0 set type monitor
sudo ip link set wlp3s0 up

# Optional: lock to a specific channel (e.g., 6)
# sudo iw dev wlp3s0 set channel 6

# Confirm monitor mode
iwconfig wlp3s0

# Switch to monitor mode