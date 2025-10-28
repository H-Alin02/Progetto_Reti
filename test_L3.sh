#!/bin/bash
# Script per testare l'API Flask su h1 con routing L3

echo ">>> INIZIO TEST L3 (Cross-Subnet)"
echo "-------------------------------------"

# IP del server API (h1)
API_SERVER="10.0.0.2:8001"

# --- Test 1: h3 -> h4 (UDP) ---
# (11.0.0.0/24 -> 192.168.1.0/24)
h3_ip="11.0.0.2"
h4_ip="192.168.1.2"
echo ">>> Test 1: h3 avvia test UDP (2M) verso h4 (${h4_ip})"
curl -X POST -d "IP_DEST=${h4_ip}&L4_proto=udp&src_rate=2M" http://${API_SERVER}/start_iperf
echo -e "\n--- Test 1 (avviato da h3) Completato ---\n"
sleep 14

# --- Test 2: h5 -> h2 (TCP) ---
# (10.8.1.0/24 -> 10.0.0.0/24)
echo ">>> Test 2: h5 avvia test TCP verso h2 (${h2_ip})"
h5_ip="10.8.1.2"
h2_ip="10.0.0.3"
curl -X POST -d "IP_DEST=${h2_ip}&L4_proto=tcp" http://${API_SERVER}/start_iperf
echo -e "\n--- Test 2 (avviato da h5) Completato ---\n"
sleep 14

# --- Test 3: h4 -> h3 (UDP High Rate) ---
# (192.168.1.0/24 -> 11.0.0.0/24)
h4_ip=192.168.1.2
h3_ip="11.0.0.2"
echo ">>> Test 3: h4 avvia test UDP (10M) verso h3 (${h3_ip})"
curl -X POST -d "IP_DEST=${h3_ip}&L4_proto=udp&src_rate=10M" http://${API_SERVER}/start_iperf
echo -e "\n--- Test 3 (avviato da h4) Completato ---\n"
sleep 14

# --- Test 4: Stop ---
echo ">>> Test 4: h2 invia comando stop a h1"
curl -X POST http://${API_SERVER}/stop_iperf
echo -e "\n--- Test 4 (Stop) Completato ---\n"


echo "-------------------------------------"
echo ">>> TEST L3 COMPLETATI"
echo "Verifica i file *_log.csv su h4, h2, h3"