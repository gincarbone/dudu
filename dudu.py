from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import subprocess
import platform
from scapy.all import ARP, Ether, srp
import paramiko
import threading


app = Flask(__name__)
CORS(app)  # Abilita CORS per tutte le route


clients = {}


def ping_host(host):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', host]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        return 'green'
    else:
        return 'red'

def network_discovery(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    devices = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in result]
    return devices

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/ping', methods=['POST'])
def ping():
    data = request.get_json()
    host = data.get('host')
    if not host:
        return jsonify({'error': 'Host is required'}), 400
    status = ping_host(host)
    return jsonify({'status': status})

@app.route('/discover', methods=['POST'])
def discover():
    data = request.get_json()
    ip_range = data.get('ip_range')
    if not ip_range:
        return jsonify({'error': 'IP range is required'}), 400
    devices = network_discovery(ip_range)
    return jsonify({'devices': devices})


if __name__ == '__main__':
    app.run(port=5000)
