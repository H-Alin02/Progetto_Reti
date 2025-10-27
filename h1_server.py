import os
import subprocess
import json
from datetime import datetime
from flask import Flask, request, jsonify

# Configurazione
LOG_FILE = 'Logs/h1_command_log.json'
app = Flask(__name__)

# Comandi permessi (sicurezza)
ALLOWED_COMMANDS = [
    'iperf',
    'killall'
]

def is_command_allowed(command_str):

    for allowed_cmd in ALLOWED_COMMANDS:
        if command_str.startswith(allowed_cmd):
            return True
    return False


@app.route("/start_iperf", methods=['POST'])
def start_iperf_handler():

    # Dati per il comando
    source_ip = request.remote_addr
    dest_ip = request.values.get('IP_DEST')
    l4_proto = request.values.get('L4_proto')
    src_rate = request.values.get('src_rate')

    # Validazione dell'input 
    if not dest_ip:
        error_msg = {'status':'error', 
                     'message':'missing IP_DEST'}
        log_request(source_ip,'start_iperf (failed)',error_msg)
        return jsonify(error_msg), 400 # Bad Request

    # Costruzione del comando iperf 
    cmd = f'iperf -c {dest_ip}'

    if l4_proto and l4_proto.lower() == 'udp':
        cmd += ' -u -p 5002'
        if src_rate:
            cmd += f' -b {src_rate}'
    elif src_rate: # default tcp, senza l4_proto
        cmd += f' -p 5001 -b {src_rate}'

    if not is_command_allowed(cmd):
        error_msg = {'status':'error', 
                     'message':'Forbidden command'}
        log_request(source_ip,cmd,error_msg)
        return jsonify(error_msg), 403 # Forbidden
    
    cmd += ' &' # esecuzione in background
    
    # Esecuzione del comando

    try:
        subprocess.run(cmd, shell=True, check=True)

        response = {'status':'OK',
                'message':'iperf command executed successfully',
                'command': cmd}
        log_request(source_ip,cmd,response)
        return jsonify(response), 200 # OK
    except Exception as e:
        error_msg = {'status':'error', 'message':str(e)}
        log_request(source_ip,cmd,error_msg)
        return jsonify(error_msg), 500 # Internal Server Error

@app.route('/stop_iperf', methods=['POST'])
def stop_iperf_handler():

    source_ip = request.remote_addr
    cmd = 'killall iperf'

    if not is_command_allowed(cmd):
        error_msg = {'status':'error', 
                     'message':'Forbidden command'}
        log_request(source_ip,cmd,error_msg)
        return jsonify(error_msg), 403 # Forbidden

    # Esecuzione comando
    try:
        # check=False per evitare errori in caso di nessun comando iperf in esecuzione
        subprocess.run(cmd, shell=True, check=False)

        response = {'status':'OK',
                'message':'killall command executed successfully'}
        log_request(source_ip,cmd,response)
        return jsonify(response), 200 # OK
    except Exception as e:
        error_msg = {'status':'error', 'message':str(e)}
        log_request(source_ip,cmd,error_msg)
        return jsonify(error_msg), 500 # Internal Server Error

# Aggiunge una riga al file log JSON
def log_request(ip, command, response):
    
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'source_ip':ip,
        'requested_command':command,
        'response': response
    }

    try:
        # Carichiamo i log precedenti se presenti
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE,'r') as f:
                logs = json.load(f)
        else:
            logs = [] # Lista vuota per i logs

        logs.append(log_entry)
        with open(LOG_FILE,'w') as f:
            json.dump(logs,f,indent=4)
    except Exception as e:
        print(f'-- Errore durante la scrittura del log: {e}')

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=8001,
        debug=False )