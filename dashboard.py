# dashboard.py
from flask import Flask, render_template_string
import json
import os
import glob

app = Flask(__name__)

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>MLS Performance Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .metric-good { color: green; font-weight: bold; }
        .metric-warning { color: orange; font-weight: bold; }
        .metric-bad { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <h1>📊 MLS Performance Dashboard</h1>
    
    <h2>Latest Test Results</h2>
    <table>
        <tr>
            <th>Test</th>
            <th>Value</th>
            <th>Status</th>
        </tr>
        {% for test, value in latest_results.items() %}
        <tr>
            <td>{{ test }}</td>
            <td>{{ value.value }}</td>
            <td class="metric-{{ value.status }}">{{ value.status }}</td>
        </tr>
        {% endfor %}
    </table>
    
    <h2>Historical Reports</h2>
    <ul>
    {% for report in reports %}
        <li><a href="/view/{{ report }}">{{ report }}</a></li>
    {% endfor %}
    </ul>
</body>
</html>
'''

@app.route('/')
def dashboard():
    # Find all performance reports
    reports = glob.glob('performance_report_*.json')
    reports.sort(reverse=True)
    
    # Load latest report
    latest_results = {}
    if reports:
        with open(reports[0], 'r') as f:
            data = json.load(f)
            if 'encryption' in data:
                latest_results['Encryption (avg)'] = {'value': f"{data['encryption']['mean']:.2f} ms", 'status': 'good' if data['encryption']['mean'] < 10 else 'warning'}
            if 'tree_rebuild' in data:
                latest_results['Tree Rebuild'] = {'value': f"{data['tree_rebuild']:.2f} ms", 'status': 'good' if data['tree_rebuild'] < 100 else 'warning'}
            if 'load' in data and 'avg_latency' in data['load']:
                latest_results['Load Test (avg)'] = {'value': f"{data['load']['avg_latency']:.2f} ms", 'status': 'good' if data['load']['avg_latency'] < 100 else 'warning'}
    
    return render_template_string(HTML_TEMPLATE, latest_results=latest_results, reports=reports[:10])

@app.route('/view/<filename>')
def view_report(filename):
    with open(filename, 'r') as f:
        data = json.load(f)
    return f"<pre>{json.dumps(data, indent=2)}</pre>"

if __name__ == '__main__':
    app.run(debug=True, port=5001)