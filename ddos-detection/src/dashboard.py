#!/usr/bin/env python3
from flask import Flask, render_template, jsonify
import time
from collections import deque
import random
import argparse
import os

app = Flask(__name__)

traffic_data = {
    'timestamps': deque(maxlen=100),
    'packet_rates': deque(maxlen=100),
    'byte_rates': deque(maxlen=100),
    'alerts': deque(maxlen=50)
}

def generate_mock_data():
    """Generate mock traffic data"""
    import threading
    while True:
        timestamp = time.time()
        base_packet_rate = 100
        base_byte_rate = 50000
        
        if random.random() < 0.05:
            packet_rate = base_packet_rate * random.uniform(5, 10)
            byte_rate = base_byte_rate * random.uniform(5, 10)
            traffic_data['alerts'].append({
                'timestamp': time.strftime('%H:%M:%S', time.localtime(timestamp)),
                'message': 'DDoS attack detected - High packet rate'
            })
        else:
            packet_rate = base_packet_rate * random.uniform(0.8, 1.2)
            byte_rate = base_byte_rate * random.uniform(0.8, 1.2)
        
        traffic_data['timestamps'].append(timestamp)
        traffic_data['packet_rates'].append(packet_rate)
        traffic_data['byte_rates'].append(byte_rate)
        
        time.sleep(1)

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/traffic_data')
def get_traffic_data():
    timestamps = [time.strftime('%H:%M:%S', time.localtime(t)) 
                  for t in traffic_data['timestamps']]
    return jsonify({
        'timestamps': list(timestamps),
        'packet_rates': list(traffic_data['packet_rates']),
        'byte_rates': list(traffic_data['byte_rates'])
    })

@app.route('/api/alerts')
def get_alerts():
    return jsonify(list(traffic_data['alerts']))

def create_template():
    os.makedirs('templates', exist_ok=True)
    
    template = '''<!DOCTYPE html>
<html>
<head>
    <title>DDoS Detection Dashboard</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        body { font-family: Arial; margin: 0; padding: 20px; background: #f0f0f0; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .panel { background: white; border-radius: 5px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .alert { background: #e74c3c; color: white; padding: 10px; margin: 5px 0; border-radius: 3px; }
        #packet-chart, #byte-chart { height: 300px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ DDoS Detection Dashboard</h1>
    </div>
    <div class="panel">
        <h2>Packet Rate</h2>
        <div id="packet-chart"></div>
    </div>
    <div class="panel">
        <h2>🚨 Alerts</h2>
        <div id="alerts"></div>
    </div>
    <script>
        function update() {
            fetch('/api/traffic_data').then(r => r.json()).then(d => {
                Plotly.newPlot('packet-chart', [{x: d.timestamps, y: d.packet_rates, type: 'scatter'}]);
            });
            fetch('/api/alerts').then(r => r.json()).then(d => {
                let html = '';
                d.reverse().forEach(a => html += `<div class="alert">${a.timestamp}: ${a.message}</div>`);
                document.getElementById('alerts').innerHTML = html || '<p>No alerts</p>';
            });
        }
        setInterval(update, 2000);
        update();
    </script>
</body>
</html>'''
    
    with open('templates/dashboard.html', 'w') as f:
        f.write(template)

def main():
    parser = argparse.ArgumentParser(description='DDoS Detection Dashboard')
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--host', default='127.0.0.1')
    args = parser.parse_args()
    
    create_template()
    
    import threading
    t = threading.Thread(target=generate_mock_data, daemon=True)
    t.start()
    
    print(f"\nDashboard URL: http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)

if __name__ == '__main__':
    main()
