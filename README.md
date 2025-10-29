# Progetto Reti di Calcolatori - A.A. 2024-2025 (Traccia 03)

Questo progetto implementa una rete emulata utilizzando Mininet, controllata da un controller SDN Ryu personalizzato che agisce come router L3 statico. Include un'API REST basata su Flask per l'avvio remoto di test di performance `iperf` tra gli host della rete.

## Struttura del Progetto

Il progetto è composto dai seguenti file principali:

* **`topology.py`**: Script Python per Mininet che definisce la topologia di rete (host, switch L3, link con specifiche di banda/latenza) e avvia i server `iperf` e l'API Flask.
* **`controller.py`**: Applicazione controller SDN basata su Ryu che implementa la logica di routing L3 statico e la gestione ARP per i 4 switch OVS (`s1`, `s2`, `s3`, `s4`). Include una gestione L2 specifica per `s1` per la subnet locale di `h1` e `h2`.
* **`h1_server.py`**: Server API REST basato su Flask, in esecuzione su `h1`. Espone gli endpoint `/start_iperf` e `/stop_iperf` per avviare e fermare test `iperf` da `h1` verso altri host.
* **`test_L3.sh`**: Script Bash per automatizzare l'esecuzione di test `iperf` tramite l'API REST.

## Dipendenze

* **Mininet VM**: Per l'emulazione della rete ho fatto uso della VM ufficiale Mininet.
* **Ryu SDN Framework**: Per eseguire il controller.
* **Flask**: Per eseguire il server API REST.
* **Python 3**: Linguaggio utilizzato per gli script.
* **iperf**: Tool per i test di performance.

## Istruzioni per l'Esecuzione

1.  **Pulizia Ambiente (Opzionale ma consigliato):**
    ```bash
    sudo mn -c
    ```

2.  **Avvio del Controller Ryu:**
    Dalla cartella `Progetto_Reti`esegui su un terminale
    ```bash
    ryu-manager controller.py
    ```

3.  **Avvio della Topologia Mininet:**
    Apri un'altro terminale nella cartella `Progetto_Reti` ed esegui
    ```bash
    sudo python3 progetto03_topology.py
    ```

4.  **Esecuzione dei Test:**
    È possibile effettuare test `curl` manuali oppure usare lo script:
    * **Test di connettività:** `mininet> pingall`
    * **Test API + L3 (Script):** `mininet> h2 bash test_l3.sh`
    * **Test API (Manuale, es. da h3 a h4):**
        ```bash
        mininet> h3 curl -X POST -d "IP_DEST=192.168.1.2&L4_proto=udp&src_rate=1M" http://10.0.0.2:8001/start_iperf
        ```

5.  **Verifica dei Log:**
    Dopo aver eseguito i test `iperf`:
    * I log delle richieste API si trovano su `h1` nel file `h1_command_log.json`.
    * I log dei risultati `iperf` si trovano su ogni host destinatario nei file `hX_tcp_log.csv` e `hX_udp_log.csv`.