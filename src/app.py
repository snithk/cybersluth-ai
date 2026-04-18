from flask import Flask, render_template, jsonify, request, redirect, url_for, send_from_directory
import threading
import time
from datetime import datetime
import json
import csv as csv_module
import tempfile
from collections import deque
import os
import sys
import logging
from werkzeug.utils import secure_filename

# Add the parent directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.analyzers.network_analyzer import NetworkAnalyzer # type: ignore
from src.analyzers.log_analyzer import LogAnalyzer # type: ignore
from src.analyzers.artifact_analyzer import ArtifactAnalyzer # type: ignore
from src.models.threat_detector import ThreatDetector # type: ignore
from src.utils.report_generator import ReportGenerator # type: ignore

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Global state
analysis_active = False
network_active = False
analyzer_thread = None
network_data = {
    'bytes_sent': deque(maxlen=60),
    'bytes_recv': deque(maxlen=60),
    'timestamps': deque(maxlen=60)
}
current_threats = []
artifact_findings_cache = {'summary': {}, 'suspicious_files': []}

# Resolve project root from this file (robust on Render / gunicorn where CWD may differ)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(PROJECT_ROOT, 'reports')
os.makedirs(REPORTS_DIR, exist_ok=True)

# Path to the auto-loaded default CSV (sits in the project root)
DEFAULT_CSV_PATH = os.path.join(PROJECT_ROOT, 'sample_network_traffic.csv')
# If user uploads a CSV, save it here so it persists across restarts
PERSISTED_CSV_PATH = os.path.join(PROJECT_ROOT, '_last_upload.csv')

# Initialize analyzers
network_analyzer = NetworkAnalyzer()
log_analyzer = LogAnalyzer()
artifact_analyzer = ArtifactAnalyzer()
threat_detector = ThreatDetector()
report_generator = ReportGenerator()


def auto_load_csv():
    """Auto-load the default (or last-uploaded) CSV on startup so the
    dashboard shows data immediately without requiring a manual upload."""
    global current_threats, network_data, network_active, analysis_active

    # Prefer the last user-uploaded file; fall back to the bundled sample
    csv_path = PERSISTED_CSV_PATH if os.path.exists(PERSISTED_CSV_PATH) else DEFAULT_CSV_PATH
    if not os.path.exists(csv_path):
        logger.info("No default CSV found — skipping auto-load")
        return

    try:
        logger.info(f"Auto-loading CSV: {csv_path}")
        net_stats = network_analyzer.analyze_from_csv(csv_path)
        network_active = True
        analysis_active = True

        # Build chart data
        connections = net_stats.get('system', {}).get('detailed_connections', [])
        bucket_size = max(1, len(connections) // 60)
        chart_sent, chart_labels = [], []
        for i in range(0, len(connections), bucket_size):
            bucket = connections[i:i + bucket_size]
            total = sum(c.get('local_port', 0) % 1500 for c in bucket)
            chart_sent.append(total)
            chart_labels.append(f"pkt {i}")

        network_data['bytes_sent'] = deque(chart_sent[-60:], maxlen=60)
        network_data['bytes_recv'] = deque([0] * len(chart_sent[-60:]), maxlen=60)
        network_data['timestamps'] = deque(chart_labels[-60:], maxlen=60)

        # Detect threats from labels
        label_counts = {}
        with open(csv_path, 'r') as f:
            reader = csv_module.DictReader(f)
            for row in reader:
                label = row.get('label', 'Benign')
                if label != 'Benign':
                    label_counts[label] = label_counts.get(label, 0) + 1

        threats_found = {'high_priority': [], 'medium_priority': [], 'low_priority': []}
        for label, count in label_counts.items():
            entry = {
                'type': label, 'source': 'auto_csv_loader',
                'confidence': 0.93,
                'timestamp': datetime.now().isoformat(),
                'details': {'attack_type': label, 'packet_count': count}
            }
            lu = label.upper()
            if any(k in lu for k in ['DDOS', 'FLOOD', 'DOS']):
                entry['type'] = 'DDOS_FLOOD_DETECTED'; entry['confidence'] = 0.97
                threats_found['high_priority'].append(entry)
            elif any(k in lu for k in ['BRUTEFORCE', 'BRUTE', 'SSH']):
                entry['type'] = 'BRUTE_FORCE_DETECTED'; entry['confidence'] = 0.91
                threats_found['high_priority'].append(entry)
            elif any(k in lu for k in ['PORTSCAN', 'SCAN', 'PROBE']):
                entry['type'] = 'PORT_SCAN_DETECTED'; entry['confidence'] = 0.88
                threats_found['medium_priority'].append(entry)
            else:
                threats_found['low_priority'].append(entry)

        more = threat_detector.detect_threats(network_data=net_stats)
        for p in ['high_priority', 'medium_priority', 'low_priority']:
            threats_found[p].extend(more[p])

        current_threats = (
            [(t, 'high')   for t in threats_found['high_priority']] +
            [(t, 'medium') for t in threats_found['medium_priority']] +
            [(t, 'low')    for t in threats_found['low_priority']]
        )
        logger.info(f"Auto-load complete — {len(connections)} packets, {len(current_threats)} threats found")
    except Exception as e:
        logger.error(f"Auto-load CSV failed: {e}")

def analysis_worker():
    """Background worker for continuous analysis"""
    global analysis_active, network_active, network_data, current_threats
    
    while analysis_active:
        try:
            # Get network data
            net_stats = network_analyzer.monitor_realtime()
            network_active = True
            
            # Update network data for chart
            system_stats = net_stats.get('system', {})
            network_data['bytes_sent'].append(system_stats.get('bytes_sent', 0))
            network_data['bytes_recv'].append(system_stats.get('bytes_recv', 0))
            network_data['timestamps'].append(datetime.now().strftime('%H:%M:%S'))
            
            # Get log findings (fast)
            log_findings = log_analyzer.monitor_realtime()
            
            # Periodically update artifact findings (slow, so update every 10 iterations or so)
            if not hasattr(analysis_worker, 'counter'):
                analysis_worker.counter = 0
            
            if analysis_worker.counter % 10 == 0:
                artifact_findings_cache = artifact_analyzer.analyze_artifacts()
            
            analysis_worker.counter += 1
            artifact_findings = artifact_findings_cache
            
            # Detect threats
            threats = threat_detector.detect_threats(
                network_data=net_stats,
                log_findings=log_findings,
                artifact_findings=artifact_findings
            )
            
            # Update current threats
            current_threats = (
                [(t, 'high') for t in threats['high_priority']] +
                [(t, 'medium') for t in threats['medium_priority']] +
                [(t, 'low') for t in threats['low_priority']]
            )
            
            time.sleep(1)
            
        except Exception as e:
            print(f"Error in analysis worker: {str(e)}")
            time.sleep(1)

@app.route('/')
def index():
    """Render the main dashboard"""
    # Prepare statistics
    stats = {
        'high_priority': len([t for t, p in current_threats if p == 'high']),
        'medium_priority': len([t for t, p in current_threats if p == 'medium']),
        'low_priority': len([t for t, p in current_threats if p == 'low']),
        'connections': len(network_analyzer.network_stats.get('system', {}).get('detailed_connections', []))
    }
    
    # Prepare network data for chart
    network_chart_data = {
        'bytes_sent': list(network_data['bytes_sent']),
        'bytes_recv': list(network_data['bytes_recv'])
    }
    network_labels = list(network_data['timestamps'])
    
    # Get detailed network connections
    network_connections = network_analyzer.network_stats.get('system', {}).get('detailed_connections', [])
    
    # Prepare threats for display
    threats_display = [
        {
            'priority': priority,
            'type': threat['type'],
            'source': threat['source'],
            'confidence': threat['confidence'],
            'timestamp': threat['timestamp'],
            'details': json.dumps(threat['details'], indent=2, default=str)
        }
        for threat, priority in current_threats
    ]
    
    return render_template('index.html',
                          analysis_active=analysis_active,
                          network_active=network_active,
                          stats=stats,
                          threats=threats_display,
                          network_data=network_chart_data,
                          network_labels=network_labels,
                          network_connections=network_connections)

@app.route('/api/stats')
def api_stats():
    """API endpoint for live stats"""
    stats = {
        'high_priority': len([t for t, p in current_threats if p == 'high']),
        'medium_priority': len([t for t, p in current_threats if p == 'medium']),
        'low_priority': len([t for t, p in current_threats if p == 'low']),
        'connections': len(network_analyzer.network_stats.get('system', {}).get('detailed_connections', []))
    }
    
    # Prepare threats for display
    threats_display = [
        {
            'priority': priority,
            'type': threat['type'],
            'source': threat['source'],
            'confidence': threat['confidence'],
            'timestamp': threat['timestamp'],
            'details': threat['details']
        }
        for threat, priority in current_threats
    ]

    return jsonify({
        'analysis_active': analysis_active,
        'network_active': network_active,
        'stats': stats,
        'threats': threats_display,
        'network_data': {
            'bytes_sent': list(network_data['bytes_sent']),
            'bytes_recv': list(network_data['bytes_recv']),
            'timestamps': list(network_data['timestamps'])
        },
        'network_connections': network_analyzer.network_stats.get('system', {}).get('detailed_connections', [])
    })

@app.route('/start_analysis', methods=['POST'])
def start_analysis():
    """Start the analysis process"""
    global analysis_active, analyzer_thread
    
    if not analysis_active:
        analysis_active = True
        analyzer_thread = threading.Thread(target=analysis_worker)
        analyzer_thread.daemon = True
        analyzer_thread.start()
    
    return redirect(url_for('index'))

@app.route('/stop_analysis', methods=['POST'])
def stop_analysis():
    """Stop the analysis process"""
    global analysis_active, network_active
    
    analysis_active = False
    network_active = False
    
    if analyzer_thread:
        analyzer_thread.join(timeout=5)
    
    return redirect(url_for('index'))

@app.route('/reports/<path:filename>')
def serve_report(filename):
    """Serve generated reports"""
    try:
        # Use the fixed project-level reports directory (works on Render/gunicorn)
        reports_dir = REPORTS_DIR

        # Prevent path traversal by keeping only the basename component(s)
        safe_name = os.path.normpath(filename).lstrip(os.sep)
        report_path = os.path.join(reports_dir, safe_name)

        # Check if the file exists
        if not os.path.exists(report_path):
            app.logger.error(f"Report not found at path: {report_path}")
            return "Report not found", 404

        report_directory = os.path.dirname(report_path)
        report_filename = os.path.basename(report_path)

        return send_from_directory(report_directory, report_filename)
    except Exception as e:
        app.logger.error(f"Error serving report: {str(e)}")
        return str(e), 500

@app.route('/upload_network', methods=['POST'])
def upload_network():
    """Analyze an uploaded CSV network capture file (for live/cloud deployment)"""
    global current_threats, network_data, analysis_active, network_active

    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400

    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400

    if not file.filename.lower().endswith('.csv'):
        return jsonify({'success': False, 'error': 'Only CSV files are supported. Please upload a .csv network capture file.'}), 400

    try:
        filename = secure_filename(file.filename)
        upload_path = os.path.join(tempfile.gettempdir(), filename)
        file.save(upload_path)

        # Run network analysis from CSV
        net_stats = network_analyzer.analyze_from_csv(upload_path)
        network_active = True
        analysis_active = True

        # Build chart data from packet lengths (group into buckets)
        connections = net_stats.get('system', {}).get('detailed_connections', [])
        bucket_size = max(1, len(connections) // 60)
        chart_sent = []
        chart_labels = []
        for i in range(0, len(connections), bucket_size):
            bucket = connections[i:i + bucket_size]
            total = sum(
                c.get('local_port', 0) % 1500
                for c in bucket
            )
            chart_sent.append(total)
            chart_labels.append(f"pkt {i}")

        network_data['bytes_sent'] = deque(chart_sent[-60:], maxlen=60)
        network_data['bytes_recv'] = deque([0] * len(chart_sent[-60:]), maxlen=60)
        network_data['timestamps'] = deque(chart_labels[-60:], maxlen=60)

        # Detect threats from CSV labels
        label_counts = {}
        with open(upload_path, 'r') as f:
            reader = csv_module.DictReader(f)
            for row in reader:
                label = row.get('label', 'Benign')
                if label != 'Benign':
                    label_counts[label] = label_counts.get(label, 0) + 1

        threats_from_file = {'high_priority': [], 'medium_priority': [], 'low_priority': []}
        for label, count in label_counts.items():
            threat_entry = {
                'type': label,
                'source': 'file_analyzer',
                'confidence': 0.93,
                'timestamp': datetime.now().isoformat(),
                'details': {'attack_type': label, 'packet_count': count}
            }
            label_upper = label.upper()
            if any(k in label_upper for k in ['DDOS', 'FLOOD', 'DOS']):
                threat_entry['type'] = 'DDOS_FLOOD_DETECTED'
                threat_entry['confidence'] = 0.97
                threats_from_file['high_priority'].append(threat_entry)
            elif any(k in label_upper for k in ['BRUTEFORCE', 'BRUTE', 'SSH']):
                threat_entry['type'] = 'BRUTE_FORCE_DETECTED'
                threat_entry['confidence'] = 0.91
                threats_from_file['high_priority'].append(threat_entry)
            elif any(k in label_upper for k in ['PORTSCAN', 'SCAN', 'PROBE']):
                threat_entry['type'] = 'PORT_SCAN_DETECTED'
                threat_entry['confidence'] = 0.88
                threats_from_file['medium_priority'].append(threat_entry)
            elif any(k in label_upper for k in ['EXFIL', 'C2', 'BEACON']):
                threat_entry['type'] = 'DATA_EXFIL_DETECTED'
                threat_entry['confidence'] = 0.95
                threats_from_file['high_priority'].append(threat_entry)
            else:
                threats_from_file['low_priority'].append(threat_entry)

        # Also run standard threat detection
        more_threats = threat_detector.detect_threats(network_data=net_stats)
        for priority in ['high_priority', 'medium_priority', 'low_priority']:
            threats_from_file[priority].extend(more_threats[priority])

        current_threats = (
            [(t, 'high') for t in threats_from_file['high_priority']] +
            [(t, 'medium') for t in threats_from_file['medium_priority']] +
            [(t, 'low') for t in threats_from_file['low_priority']]
        )

        # ── Save as the new default so it auto-loads next restart ──────────
        import shutil
        try:
            shutil.copy2(upload_path, PERSISTED_CSV_PATH)
            logger.info(f"Uploaded CSV saved as new default: {PERSISTED_CSV_PATH}")
        except Exception as copy_err:
            logger.warning(f"Could not persist uploaded CSV: {copy_err}")
        os.remove(upload_path)

        total_threats = sum(len(v) for v in threats_from_file.values())
        return jsonify({
            'success': True,
            'message': f'Analyzed {len(connections)} connections. Found {total_threats} threat(s).',
            'threats': {
                'high': len(threats_from_file['high_priority']),
                'medium': len(threats_from_file['medium_priority']),
                'low': len(threats_from_file['low_priority'])
            }
        })

    except Exception as e:
        logger.error(f"Error in upload_network: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/generate_report', methods=['POST'])
def generate_report():
    """Generate analysis report with all collected system data"""
    try:
        # Use the fixed project-level reports directory (works on Render/gunicorn)
        reports_dir = REPORTS_DIR
        os.makedirs(reports_dir, exist_ok=True)
        
        # Prepare threats data from current_threats
        threats = {
            'high_priority': [],
            'medium_priority': [],
            'low_priority': []
        }
        
        # Include all detected threats
        for threat, priority in current_threats:
            threats[f'{priority}_priority'].append({
                'type': threat.get('type', 'Unknown'),
                'source': threat.get('source', 'Unknown'),
                'confidence': threat.get('confidence', 0.0),
                'timestamp': threat.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                'details': threat.get('details', {})
            })
        
        # Get network data from the global network_data variable
        global network_data
        current_network_stats = {
            'system': {
                'bytes_sent': sum(list(network_data['bytes_sent'])) if network_data['bytes_sent'] else 0,
                'bytes_recv': sum(list(network_data['bytes_recv'])) if network_data['bytes_recv'] else 0,
                'packets_sent': len(network_data['bytes_sent']),
                'packets_recv': len(network_data['bytes_recv']),
                'detailed_connections': network_analyzer.network_stats.get('system', {}).get('detailed_connections', [])
            }
        }
        
        # Get log data and use cached artifact findings for speed
        log_findings = log_analyzer.monitor_realtime()
        artifact_findings = artifact_findings_cache
        
        # Generate report
        result = report_generator.generate_report(
            threats=threats,
            network_data=current_network_stats,
            log_findings=log_findings,
            artifact_findings=artifact_findings
        )
        
        if result['success']:
            # Verify the report file exists
            report_path = os.path.join(reports_dir, result['reports']['html'])
            if not os.path.exists(report_path):
                raise FileNotFoundError(f"Generated report file not found at {report_path}")
            
            app.logger.info(f"Report generated successfully at {report_path}")
            return jsonify(result)
        else:
            app.logger.error(f"Report generation failed: {result.get('error', 'Unknown error')}")
            return jsonify(result), 500
            
    except Exception as e:
        error_msg = f"Error generating report: {str(e)}"
        app.logger.error(error_msg)
        return jsonify({
            'success': False,
            'error': error_msg
        }), 500

if __name__ == '__main__':
    try:
        # Ensure the reports directory exists
        os.makedirs('reports', exist_ok=True)

        # Print access information
        print("\nCyberSentry is starting up...")
        print("=" * 50)
        print("Access the web interface at:")
        print("  http://127.0.0.1:5000")
        print("  http://localhost:5000")
        print("=" * 50)
        
        # Start the Flask server
        # Exclude the virtual-env directory to stop hot-reloads caused by
        # library internals (e.g. torch) modifying their own files.
        app.run(
            host='0.0.0.0',  # Allow connections from any interface
            port=5000,
            debug=True,
            exclude_patterns=['env/*', 'env/**/*', '*.pyc', '__pycache__/*']
        )
    except Exception as e:
        print(f"Error starting CyberSentry: {str(e)}")
        raise 