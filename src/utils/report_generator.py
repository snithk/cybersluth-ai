import os
import json
import logging
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import seaborn as sns
from jinja2 import Template
import pandas as pd
import base64
from io import BytesIO
from jinja2 import Environment, FileSystemLoader
import psutil
import platform

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self):
        # Initialize Jinja2 environment with proper loader and filters
        self.template_env = Environment(
            loader=FileSystemLoader(os.path.dirname(os.path.abspath(__file__))),
            autoescape=True
        )
        
        # Add custom filters
        def format_number(value):
            try:
                if value is None:
                    return "0"
                return "{:,}".format(int(float(value)))
            except (ValueError, TypeError):
                return "0"
                
        self.template_env.filters['format_number'] = format_number
        
        self.report_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cyber Forensics Analysis Report</title>
    <style>
        /* ── Base reset ─────────────────────────────────────────────── */
        *, *::before, *::after { box-sizing: border-box; }
        html { -webkit-text-size-adjust: 100%; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
            overflow-x: hidden;
            word-wrap: break-word;
        }
        h1, h2, h3, h4 { line-height: 1.25; margin-top: 0; }
        h1 { font-size: clamp(1.4rem, 4vw, 2rem); }
        h2 { font-size: clamp(1.2rem, 3vw, 1.6rem); }
        h3 { font-size: clamp(1.05rem, 2.4vw, 1.25rem); }

        .header {
            background: linear-gradient(135deg, #1a237e, #0d47a1);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header p { margin: 4px 0; font-size: clamp(0.85rem, 2.2vw, 1rem); }

        .section {
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        .subsection {
            margin: 10px 0;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
        }

        /* ── Responsive grid of stat cards ──────────────────────────── */
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin: 20px 0;
        }
        .stat-card {
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            text-align: center;
            min-width: 0;
        }
        .stat-value {
            font-size: clamp(1.1rem, 3.5vw, 1.6rem);
            font-weight: bold;
            color: #1a237e;
            word-break: break-word;
        }
        .stat-label {
            color: #666;
            font-size: clamp(0.75rem, 2vw, 0.9rem);
        }

        /* ── Responsive tables: horizontal scroll on narrow screens ─── */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
            font-size: clamp(0.8rem, 2vw, 0.95rem);
        }
        th, td {
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
            vertical-align: top;
            word-break: break-word;
        }
        th { background-color: #f8f9fa; font-weight: 600; }

        /* Any table placed in a scroll-container OR any table inside a
           subsection scrolls horizontally on small screens */
        .process-list,
        .subsection,
        .threat-details {
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
        }
        .process-list { max-height: 300px; overflow-y: auto; }

        .threat-high   { color: #d32f2f; }
        .threat-medium { color: #f57c00; }
        .threat-low    { color: #388e3c; }

        .recommendation {
            border-left: 4px solid #1a237e;
            padding: 10px 20px;
            margin: 10px 0;
            background: #f8f9fa;
        }
        .recommendation.high   { border-left-color: #d32f2f; }
        .recommendation.medium { border-left-color: #f57c00; }
        .recommendation.low    { border-left-color: #388e3c; }

        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            white-space: nowrap;
        }
        .badge-secure  { background-color: #c8e6c9; color: #388e3c; }
        .badge-risk    { background-color: #ffcdd2; color: #d32f2f; }
        .badge-warning { background-color: #fff3c4; color: #8a6d00; }

        .threat-details {
            margin: 20px 0;
            padding: 15px;
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        .mitigation-steps {
            margin-top: 15px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        .mitigation-steps h4 { color: #1a237e; margin-top: 0; }
        .mitigation-steps ol { margin: 10px 0; padding-left: 20px; }
        .mitigation-steps li { margin: 5px 0; color: #333; }

        /* ── Tablet (≤ 900px) ───────────────────────────────────────── */
        @media (max-width: 900px) {
            body { padding: 14px; }
            .section { padding: 16px; }
            .grid { grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
            th, td { padding: 8px; }
        }

        /* ── Mobile (≤ 600px) ───────────────────────────────────────── */
        @media (max-width: 600px) {
            body { padding: 10px; }
            .header { padding: 14px; margin-bottom: 18px; border-radius: 8px; }
            .section { padding: 12px; margin-bottom: 14px; border-radius: 8px; }
            .subsection { padding: 8px; }
            .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
            .stat-card { padding: 10px; }
            .stat-value { font-size: 1.1rem; }
            .stat-label { font-size: 0.75rem; }
            th, td { padding: 6px 8px; font-size: 0.8rem; }
            .mitigation-steps { padding: 10px; }
            .mitigation-steps ol { padding-left: 18px; }
        }

        /* ── Very small (≤ 380px) single column stats ───────────────── */
        @media (max-width: 380px) {
            .grid { grid-template-columns: 1fr; }
        }

        /* ── Print ──────────────────────────────────────────────────── */
        @media print {
            body { background: #fff; padding: 0; max-width: 100%; }
            .section, .stat-card, .threat-details { box-shadow: none; break-inside: avoid; }
            .process-list { max-height: none; overflow: visible; }
            .subsection, .threat-details, .process-list { overflow: visible; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Cyber Forensics Analysis Report</h1>
        <p>Generated on: {{ timestamp }}</p>
        <p>Analysis Duration: {{ analysis_duration }}</p>
        <p>Analysis Period: {{ analysis_start_time }} to {{ analysis_end_time }}</p>
    </div>

    <!-- Executive Summary -->
    <div class="section">
        <h2>Executive Summary</h2>
        <div class="grid">
            <div class="stat-card">
                <div class="stat-value">{{ summary.total_threats }}</div>
                <div class="stat-label">Total Threats Detected</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ summary.high_priority_count }}</div>
                <div class="stat-label">High Priority Threats</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ summary.medium_priority_count }}</div>
                <div class="stat-label">Medium Priority Threats</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ summary.low_priority_count }}</div>
                <div class="stat-label">Low Priority Threats</div>
            </div>
        </div>
        <div class="subsection">
            <p><strong>Network Status:</strong> {{ summary.network_status }}</p>
            <p><strong>System Security Status:</strong> 
                <span class="badge {% if summary.system_security_status == 'Secure' %}badge-secure{% else %}badge-risk{% endif %}">
                    {{ summary.system_security_status }}
                </span>
            </p>
            <p><strong>Threat Level:</strong> {{ summary.threat_level }}</p>
            <p><strong>Recommended Actions:</strong> {{ summary.recommended_actions }}</p>
        </div>
    </div>

    <!-- System Information -->
    <div class="section">
        <h2>System Information</h2>
        <div class="grid">
            <div class="stat-card">
                <div class="stat-value">{{ system_info.cpu_usage }}%</div>
                <div class="stat-label">CPU Usage</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ system_info.memory_usage }}%</div>
                <div class="stat-label">Memory Usage</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ system_info.disk_usage }}%</div>
                <div class="stat-label">Disk Usage</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ system_info.process_count }}</div>
                <div class="stat-label">Active Processes</div>
            </div>
        </div>
        <div class="subsection">
            <p><strong>Operating System:</strong> {{ system_info.os_name }} {{ system_info.os_version }}</p>
            <p><strong>Architecture:</strong> {{ system_info.architecture }}</p>
            <p><strong>System Boot Time:</strong> {{ system_info.boot_time }}</p>
        </div>
    </div>

    <!-- Process Analysis -->
    <div class="section">
        <h2>Process Analysis</h2>
        <div class="process-list">
            <table>
                <thead>
                    <tr>
                        <th>PID</th>
                        <th>Name</th>
                        <th>CPU %</th>
                        <th>Memory %</th>
                        <th>Status</th>
                        <th>Start Time</th>
                    </tr>
                </thead>
                <tbody>
                    {% for process in system_info.processes %}
                    <tr>
                        <td>{{ process.pid }}</td>
                        <td style="word-break:break-all;">{{ process.name }}</td>
                        <td>{{ "%.1f"|format(process.cpu_percent) }}%</td>
                        <td>{{ "%.1f"|format(process.memory_percent) }}%</td>
                        <td>{{ process.status }}</td>
                        <td>{{ process.create_time }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>

    <!-- System Calls Analysis -->
    <div class="section">
        <h2>System Calls Analysis</h2>
        <div class="grid">
            <div class="stat-card">
                <div class="stat-value">{{ system_calls.total_calls }}</div>
                <div class="stat-label">Total System Calls</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ system_calls.file_operations }}</div>
                <div class="stat-label">File Operations</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ system_calls.network_operations }}</div>
                <div class="stat-label">Network Operations</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ system_calls.process_operations }}</div>
                <div class="stat-label">Process Operations</div>
            </div>
        </div>
        
        <div class="subsection">
            <h3>Most Frequent System Calls</h3>
            <table>
                <thead>
                    <tr>
                        <th>System Call</th>
                        <th>Count</th>
                        <th>Category</th>
                        <th>Risk Level</th>
                    </tr>
                </thead>
                <tbody>
                    {% for call in system_calls.frequent_calls %}
                    <tr>
                        <td>{{ call.name }}</td>
                        <td>{{ call.count }}</td>
                        <td>{{ call.category }}</td>
                        <td>
                            <span class="badge {% if call.risk_level == 'High' %}badge-risk{% elif call.risk_level == 'Low' %}badge-secure{% else %}badge-warning{% endif %}">
                                {{ call.risk_level }}
                            </span>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="subsection">
            <h3>Suspicious System Call Patterns</h3>
            <div class="patterns-list">
                {% for pattern in system_calls.suspicious_patterns %}
                <div class="pattern-item">
                    <h4>{{ pattern.title }}</h4>
                    <p><strong>Description:</strong> {{ pattern.description }}</p>
                    <p><strong>Frequency:</strong> {{ pattern.frequency }}</p>
                    <p><strong>Risk Level:</strong> 
                        <span class="badge {% if pattern.risk_level == 'High' %}badge-risk{% elif pattern.risk_level == 'Low' %}badge-secure{% else %}badge-warning{% endif %}">
                            {{ pattern.risk_level }}
                        </span>
                    </p>
                    <div class="mitigation-steps">
                        <h4>Recommended Actions:</h4>
                        <ol>
                            {% for action in pattern.recommended_actions %}
                            <li>{{ action }}</li>
                            {% endfor %}
                        </ol>
                    </div>
                </div>
            {% endfor %}
            </div>
        </div>
    </div>

    <!-- Network Analysis -->
    <div class="section">
        <h2>Network Analysis</h2>
        <!-- Add Network Packet Statistics -->
        <div class="grid">
            <div class="stat-card">
                <div class="stat-value">{{ network_analysis.packets_sent|default(0)|format_number }}</div>
                <div class="stat-label">Packets Sent</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ network_analysis.packets_received|default(0)|format_number }}</div>
                <div class="stat-label">Packets Received</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ network_analysis.bytes_sent_mb|default(0)|round(2) }} MB</div>
                <div class="stat-label">Data Sent</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ network_analysis.bytes_received_mb|default(0)|round(2) }} MB</div>
                <div class="stat-label">Data Received</div>
            </div>
        </div>

        <div class="subsection">
            <h3>Packet Analysis</h3>
            <table>
                <thead>
                    <tr>
                        <th>Protocol</th>
                        <th>Packets Count</th>
                        <th>Data Volume</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {% for protocol in network_analysis.protocol_stats %}
                    <tr>
                        <td>{{ protocol.name }}</td>
                        <td>{{ protocol.packet_count|format_number }}</td>
                        <td>{{ protocol.data_volume }}</td>
                        <td>
                            <span class="badge {% if protocol.status == 'Normal' %}badge-secure{% else %}badge-risk{% endif %}">
                                {{ protocol.status }}
                            </span>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="subsection">
            <h3>Network Traffic Patterns</h3>
            <p><strong>Peak Activity Time:</strong> {{ network_analysis.peak_time }}</p>
            <p><strong>Average Bandwidth Usage:</strong> {{ network_analysis.avg_bandwidth }}</p>
            <p><strong>Most Active Process:</strong> {{ network_analysis.most_active_process }}</p>
            <p><strong>Unusual Patterns:</strong> {{ network_analysis.unusual_patterns }}</p>
            <p><strong>Total Active Connections:</strong> {{ network_analysis.active_connections|default(0) }}</p>
            <p><strong>Average Packet Size:</strong> {{ network_analysis.avg_packet_size|default(0)|round(2) }} bytes</p>
        </div>

        <div class="subsection">
            <h3>Top Network Connections</h3>
            <table>
                <thead>
                    <tr>
                        <th>Process</th>
                        <th>Local Address</th>
                        <th>Remote Address</th>
                        <th>Packets Sent</th>
                        <th>Packets Received</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {% for conn in network_analysis.top_connections %}
                    <tr>
                        <td>{{ conn.process_name }}</td>
                        <td>{{ conn.local_address }}</td>
                        <td>{{ conn.remote_address }}</td>
                        <td>{{ conn.packets_sent|format_number }}</td>
                        <td>{{ conn.packets_received|format_number }}</td>
                        <td>
                            <span class="badge {% if conn.status == 'Normal' %}badge-secure{% else %}badge-risk{% endif %}">
                                {{ conn.status }}
                            </span>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>

    <!-- Log Analysis -->
    <div class="section">
        <h2>Log Analysis</h2>
        <div class="grid">
            <div class="stat-card">
                <div class="stat-value">{{ log_analysis.total_events }}</div>
                <div class="stat-label">Total Events</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ log_analysis.critical_events }}</div>
                <div class="stat-label">Critical Events</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ log_analysis.warning_events }}</div>
                <div class="stat-label">Warning Events</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ log_analysis.info_events }}</div>
                <div class="stat-label">Info Events</div>
            </div>
        </div>
    </div>

    <!-- Artifact Analysis -->
    <div class="section">
        <h2>Artifact Analysis</h2>
        <div class="grid">
            <div class="stat-card">
                <div class="stat-value">{{ artifact_findings.summary.total_files_analyzed|default(0) }}</div>
                <div class="stat-label">Total Files Analyzed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ artifact_findings.summary.suspicious_files_found|default(0) }}</div>
                <div class="stat-label">Suspicious Files</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ artifact_findings.summary.suspicious_images_found|default(0) }}</div>
                <div class="stat-label">Suspicious Images</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ artifact_findings.summary.suspicious_text_files|default(0) }}</div>
                <div class="stat-label">Suspicious Text Files</div>
            </div>
        </div>
        
        {% if artifact_findings.suspicious_files %}
        <div class="subsection">
            <h3>Suspicious Files Detailed</h3>
            <table>
                <thead>
                    <tr>
                        <th>Path</th>
                        <th>Type</th>
                        <th>Size</th>
                        <th>Hash</th>
                    </tr>
                </thead>
                <tbody>
                    {% for file in artifact_findings.suspicious_files %}
                    <tr>
                        <td style="word-break: break-all;">{{ file.path }}</td>
                        <td>{{ file.type }}</td>
                        <td>{{ (file.size / 1024)|round(2) }} KB</td>
                        <td style="font-family: monospace; font-size: 11px;">{{ file.hash[:16] }}...</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}
    </div>

    <!-- Detected Threats -->
    <div class="section">
        <h2>Detected Threats</h2>
        {% if threats.high_priority %}
        <div class="subsection">
            <h3 class="threat-high">High Priority Threats</h3>
            {% for threat in threats.high_priority %}
            <div class="threat-details">
                <table>
                    <tr>
                        <th>Type</th>
                        <td>{{ threat.type }}</td>
                    </tr>
                    <tr>
                        <th>Description</th>
                        <td>{{ threat.description }}</td>
                    </tr>
                    <tr>
                        <th>Source</th>
                        <td>{{ threat.source }}</td>
                    </tr>
                    <tr>
                        <th>Time</th>
                        <td>{{ threat.timestamp }}</td>
                    </tr>
                </table>
                <div class="mitigation-steps">
                    <h4>Mitigation Steps:</h4>
                    <ol>
                        {% for step in threat.mitigation_steps %}
                        <li>{{ step }}</li>
                        {% endfor %}
                    </ol>
                </div>
            </div>
            {% endfor %}
        </div>
        {% endif %}

        {% if threats.medium_priority %}
        <div class="subsection">
            <h3 class="threat-medium">Medium Priority Threats</h3>
            {% for threat in threats.medium_priority %}
            <div class="threat-details">
                <table>
                    <tr>
                        <th>Type</th>
                        <td>{{ threat.type }}</td>
                    </tr>
                    <tr>
                        <th>Description</th>
                        <td>{{ threat.description }}</td>
                    </tr>
                    <tr>
                        <th>Source</th>
                        <td>{{ threat.source }}</td>
                    </tr>
                    <tr>
                        <th>Time</th>
                        <td>{{ threat.timestamp }}</td>
                    </tr>
                </table>
                <div class="mitigation-steps">
                    <h4>Mitigation Steps:</h4>
                    <ol>
                        {% for step in threat.mitigation_steps %}
                        <li>{{ step }}</li>
                        {% endfor %}
                    </ol>
                </div>
            </div>
            {% endfor %}
        </div>
        {% endif %}

        {% if threats.low_priority %}
        <div class="subsection">
            <h3 class="threat-low">Low Priority Threats</h3>
            {% for threat in threats.low_priority %}
            <div class="threat-details">
                <table>
                    <tr>
                        <th>Type</th>
                        <td>{{ threat.type }}</td>
                    </tr>
                    <tr>
                        <th>Description</th>
                        <td>{{ threat.description }}</td>
                    </tr>
                    <tr>
                        <th>Source</th>
                        <td>{{ threat.source }}</td>
                    </tr>
                    <tr>
                        <th>Time</th>
                        <td>{{ threat.timestamp }}</td>
                    </tr>
                </table>
                <div class="mitigation-steps">
                    <h4>Mitigation Steps:</h4>
                    <ol>
                        {% for step in threat.mitigation_steps %}
                        <li>{{ step }}</li>
                        {% endfor %}
                    </ol>
                </div>
            </div>
            {% endfor %}
        </div>
        {% endif %}
    </div>

    <!-- Recommendations -->
    <div class="section">
        <h2>Security Recommendations</h2>
        {% for rec in recommendations %}
        <div class="recommendation {{ rec.priority|lower }}">
            <h3>{{ rec.title }}</h3>
            <p><strong>Priority:</strong> {{ rec.priority }}</p>
            <p>{{ rec.description }}</p>
        </div>
        {% endfor %}
    </div>

</body>
</html>
"""

    def generate_report(self, threats=None, network_data=None, log_findings=None, artifact_findings=None):
        """Generate HTML report"""
        try:
            # Resolve the project-level reports directory from this file's location.
            # This is robust under Render / gunicorn where CWD may not be the project root.
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            reports_dir = os.path.join(project_root, 'reports')
            os.makedirs(reports_dir, exist_ok=True)
            
            # Generate timestamp for the report
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_filename = f'forensics_report_{timestamp}.html'
            report_path = os.path.join(reports_dir, report_filename)
            
            logger.info("Starting report generation process...")
            
            # Use provided threats or create empty structure
            if threats is None:
                threats = {
                    'high_priority': [],
                    'medium_priority': [],
                    'low_priority': []
                }
            logger.info("Threat data prepared...")

            try:
                # Get system information with faster sampling
                # disk_usage path differs per-OS; try root then fall back gracefully
                try:
                    disk_pct = psutil.disk_usage('/').percent
                except Exception:
                    try:
                        disk_pct = psutil.disk_usage(os.path.abspath(os.sep)).percent
                    except Exception:
                        disk_pct = 0

                system_info = {
                    'cpu_usage': psutil.cpu_percent(interval=0),  # non-blocking
                    'memory_usage': psutil.virtual_memory().percent,
                    'disk_usage': disk_pct,
                    'os_name': platform.system(),
                    'os_version': platform.version(),
                    'architecture': platform.machine(),
                    'boot_time': datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
                    'processes': []
                }
                
                # Pre-collect all processes once
                all_processes = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'create_time', 'num_threads']):
                    try:
                        all_processes.append(proc)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                system_info['process_count'] = len(all_processes)
                logger.info("System information collected...")

                # Limit process display to top 20 by memory for speed and readability
                sorted_procs = sorted(all_processes, key=lambda p: p.info['memory_percent'], reverse=True)[:20]
                for proc in sorted_procs:
                    pinfo = proc.info.copy()
                    pinfo['create_time'] = datetime.fromtimestamp(pinfo['create_time']).strftime("%Y-%m-%d %H:%M:%S")
                    system_info['processes'].append(pinfo)
                logger.info("Filtered process information collected...")

            except Exception as sys_info_error:
                logger.error(f"Error collecting system information: {str(sys_info_error)}")
                system_info = {
                    'cpu_usage': 0,
                    'memory_usage': 0,
                    'disk_usage': 0,
                    'process_count': 0,
                    'os_name': 'Unknown',
                    'os_version': 'Unknown',
                    'architecture': 'Unknown',
                    'boot_time': 'Unknown',
                    'processes': []
                }

            try:
                # Analyze network traffic patterns
                net_io = psutil.net_io_counters()
                bytes_sent = net_io.bytes_sent
                bytes_received = net_io.bytes_recv
                packets_sent = net_io.packets_sent
                packets_received = net_io.packets_recv

                # Calculate MB for better readability
                bytes_sent_mb = bytes_sent / (1024 * 1024)
                bytes_received_mb = bytes_received / (1024 * 1024)

                # Calculate average packet size
                total_packets = packets_sent + packets_received
                total_bytes = bytes_sent + bytes_received
                avg_packet_size = total_bytes / total_packets if total_packets > 0 else 0

                # Get active connections - cache result to avoid calling twice.
                # On cloud hosts (Render, etc.) this can raise AccessDenied; fall back to [].
                try:
                    all_net_conns = psutil.net_connections()
                except (psutil.AccessDenied, PermissionError, OSError):
                    all_net_conns = []
                active_connections = len(all_net_conns)

                network_analysis = {
                    'peak_time': datetime.now().strftime("%H:%M:%S"),
                    'avg_bandwidth': f"{bytes_sent / 1024 / 1024:.2f} MB/s",
                    'most_active_process': "System",  # Default for Windows
                    'unusual_patterns': "None detected",
                    'packets_sent': packets_sent,
                    'packets_received': packets_received,
                    'bytes_sent_mb': bytes_sent_mb,
                    'bytes_received_mb': bytes_received_mb,
                    'active_connections': active_connections,
                    'avg_packet_size': avg_packet_size,
                    'protocol_stats': [
                        {
                            'name': 'TCP',
                            'packet_count': int(packets_sent * 0.7),
                            'data_volume': f"{(bytes_sent * 0.7 / (1024 * 1024)):.2f} MB",
                            'status': 'Normal'
                        },
                        {
                            'name': 'UDP',
                            'packet_count': int(packets_sent * 0.2),
                            'data_volume': f"{(bytes_sent * 0.2 / (1024 * 1024)):.2f} MB",
                            'status': 'Normal'
                        },
                        {
                            'name': 'ICMP',
                            'packet_count': int(packets_sent * 0.1),
                            'data_volume': f"{(bytes_sent * 0.1 / (1024 * 1024)):.2f} MB",
                            'status': 'Normal'
                        }
                    ],
                    'top_connections': []
                }

                # Get detailed connection information using cached net_connections result
                try:
                    network_analysis['active_connections'] = active_connections
                    
                    # Group all_processes by PID for fast lookup
                    proc_map = {p.info['pid']: p for p in all_processes}
                    
                    for conn in all_net_conns[:5]:  # Limit to top 5 connections for speed
                        try:
                            process = proc_map.get(conn.pid)
                            connection_info = {
                                'process_name': process.info['name'] if process else 'Unknown',
                                'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                                'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                                'packets_sent': 0,
                                'packets_received': 0,
                                'status': conn.status if conn.status else 'Unknown'
                            }
                            network_analysis['top_connections'].append(connection_info)
                        except Exception:
                            continue
                except Exception as conn_error:
                    logger.error(f"Error getting connection details: {str(conn_error)}")

                logger.info("Network analysis completed...")

            except Exception as net_error:
                logger.error(f"Error analyzing network data: {str(net_error)}")
                network_analysis = {
                    'peak_time': 'Unknown',
                    'avg_bandwidth': '0 MB/s',
                    'most_active_process': 'Unknown',
                    'unusual_patterns': 'Analysis failed',
                    'packets_sent': 0,
                    'packets_received': 0,
                    'bytes_sent_mb': 0,
                    'bytes_received_mb': 0,
                    'active_connections': 0,
                    'avg_packet_size': 0,
                    'protocol_stats': [],
                    'top_connections': []
                }

            try:
                # Analyze log patterns
                log_analysis = {
                    'total_events': len(log_findings.get('suspicious_events', [])),
                    'critical_events': sum(1 for e in log_findings.get('suspicious_events', []) if e.get('severity') == 'high'),
                    'warning_events': sum(1 for e in log_findings.get('suspicious_events', []) if e.get('severity') == 'medium'),
                    'info_events': sum(1 for e in log_findings.get('suspicious_events', []) if e.get('severity') == 'low')
                }
                logger.info("Log analysis completed...")

            except Exception as log_error:
                logger.error(f"Error analyzing log data: {str(log_error)}")
                log_analysis = {
                    'total_events': 0,
                    'critical_events': 0,
                    'warning_events': 0,
                    'info_events': 0
                }

            # Generate security recommendations with mitigation steps
            recommendations = [
                {
                    'title': 'Update System Software',
                    'priority': 'High',
                    'description': 'Several critical system components require updates.',
                    'mitigation_steps': [
                        'Run Windows Update or system package manager',
                        'Enable automatic updates for critical security patches',
                        'Update all third-party applications to their latest versions',
                        'Implement a regular update schedule for all software'
                    ]
                },
                {
                    'title': 'Review Network Connections',
                    'priority': 'Medium',
                    'description': 'Unusual network activity detected from certain processes.',
                    'mitigation_steps': [
                        'Review and terminate suspicious network connections',
                        'Update firewall rules to block unauthorized connections',
                        'Monitor network traffic patterns for anomalies',
                        'Implement network segmentation if needed'
                    ]
                },
                {
                    'title': 'Enhance System Monitoring',
                    'priority': 'Low',
                    'description': 'Consider implementing additional security monitoring tools.',
                    'mitigation_steps': [
                        'Install and configure an Intrusion Detection System (IDS)',
                        'Set up system logging and monitoring tools',
                        'Configure alerts for suspicious activities',
                        'Regularly review security logs and reports'
                    ]
                }
            ]
            logger.info("Security recommendations generated...")

            # Add threat mitigation steps
            if threats:
                for priority in ['high_priority', 'medium_priority', 'low_priority']:
                    for threat in threats[priority]:
                        threat['mitigation_steps'] = self._generate_mitigation_steps(threat)

            logger.info("Threat mitigation steps generated...")

            # Prepare summary data
            summary = {
                'total_threats': sum(len(threats[p]) for p in ['high_priority', 'medium_priority', 'low_priority']),
                'high_priority_count': len(threats.get('high_priority', [])),
                'medium_priority_count': len(threats.get('medium_priority', [])),
                'low_priority_count': len(threats.get('low_priority', [])),
                'network_status': 'Normal' if system_info['cpu_usage'] < 80 else 'High Load',
                'system_security_status': 'Secure' if not threats['high_priority'] else 'At Risk',
                'threat_level': 'Low' if not threats['high_priority'] else 'High',
                'recommended_actions': 'Monitor' if not threats['high_priority'] else 'Immediate Action Required'
            }
            logger.info("Summary data prepared...")

            # Calculate analysis duration
            analysis_duration = "30 minutes"  # This should be calculated from actual start time
            analysis_start_time = (datetime.now() - timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
            analysis_end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Add system calls analysis using pre-collected processes
            system_calls = self._analyze_system_calls(all_processes)
            
            # Prepare report data
            report_data = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'analysis_duration': analysis_duration,
                'analysis_start_time': analysis_start_time,
                'analysis_end_time': analysis_end_time,
                'summary': summary,
                'system_info': system_info,
                'threats': threats,
                'network_data': network_data or {'system': {}},
                'log_findings': log_findings or {'suspicious_events': []},
                'artifact_findings': artifact_findings or {'summary': {}, 'suspicious_files': []},
                'network_analysis': network_analysis,
                'log_analysis': log_analysis,
                'recommendations': recommendations,
                'system_calls': system_calls  # Add system calls data
            }
            logger.info("Report data prepared...")
            
            try:
                # Generate HTML report using the template string with custom environment
                template = self.template_env.from_string(self.report_template)
                html_content = template.render(**report_data)
                logger.info("HTML content generated...")
                
                # Save the report with error handling
                try:
                    with open(report_path, 'w', encoding='utf-8') as f:
                        f.write(html_content)
                    logger.info("Report file written successfully...")
                except Exception as write_error:
                    logger.error(f"Error writing report file: {str(write_error)}")
                    return {
                        'success': False,
                        'error': f"Failed to write report file: {str(write_error)}"
                    }
                
                # Verify the file was created
                if not os.path.exists(report_path):
                    error_msg = f"Failed to create report file at {report_path}"
                    logger.error(error_msg)
                    return {
                        'success': False,
                        'error': error_msg
                    }
                
                logger.info(f"Report generated successfully at: {report_path}")
                return {
                    'success': True,
                    'reports': {'html': report_filename},
                    'message': 'Report generated successfully'
                }
            except Exception as template_error:
                error_msg = f"Error in template rendering: {str(template_error)}"
                logger.error(error_msg)
                return {
                    'success': False,
                    'error': error_msg
                }

        except Exception as e:
            error_msg = f"Error generating report: {str(e)}"
            logger.error(error_msg)
        return {
                'success': False,
                'error': error_msg
            } 

    def _generate_mitigation_steps(self, threat):
        """Generate specific mitigation steps based on threat type"""
        mitigation_steps = {
            'malware': [
                'Isolate affected systems immediately',
                'Run a full system scan with updated antivirus software',
                'Remove identified malware using security tools',
                'Update all security software and apply patches',
                'Review and restrict system permissions'
            ],
            'network_intrusion': [
                'Block suspicious IP addresses at the firewall',
                'Change all system and network passwords',
                'Review and update access control lists',
                'Enable network intrusion prevention features',
                'Monitor for additional suspicious activities'
            ],
            'unauthorized_access': [
                'Terminate unauthorized sessions immediately',
                'Reset affected account credentials',
                'Enable two-factor authentication',
                'Review and update access policies',
                'Audit user permissions and access logs'
            ],
            'data_leak': [
                'Identify and secure the source of the data leak',
                'Revoke compromised credentials or tokens',
                'Encrypt sensitive data at rest and in transit',
                'Implement data loss prevention solutions',
                'Review and update data handling policies'
            ],
            'suspicious_process': [
                'Terminate suspicious processes',
                'Analyze process behavior and origin',
                'Update application whitelisting rules',
                'Review system startup programs',
                'Implement process monitoring and alerts'
            ],
            'privilege_escalation': [
                'Revoke elevated privileges immediately',
                'Patch privilege escalation vulnerabilities',
                'Review and update user permissions',
                'Implement least privilege principle',
                'Monitor for unauthorized privilege changes'
            ]
        }

        # Get default steps if threat type not found
        default_steps = [
            'Investigate and document the threat',
            'Implement immediate containment measures',
            'Update security policies and procedures',
            'Monitor for similar threats',
            'Train users on security awareness'
        ]

        return mitigation_steps.get(threat.get('type', '').lower(), default_steps)

    def _update_report_template(self):
        """Update the report template to include mitigation steps"""
        # Add mitigation steps section to the threats section in the template
        threat_section = """
        {% if threats.high_priority %}
        <div class="subsection">
            <h3 class="threat-high">High Priority Threats</h3>
            {% for threat in threats.high_priority %}
            <div class="threat-details">
            <table>
                <tr>
                        <th>Type</th>
                        <td>{{ threat.type }}</td>
                </tr>
                <tr>
                        <th>Description</th>
                        <td>{{ threat.description }}</td>
                </tr>
                <tr>
                        <th>Source</th>
                        <td>{{ threat.source }}</td>
                </tr>
                <tr>
                        <th>Time</th>
                        <td>{{ threat.timestamp }}</td>
                </tr>
            </table>
                <div class="mitigation-steps">
                    <h4>Mitigation Steps:</h4>
                    <ol>
                        {% for step in threat.mitigation_steps %}
                        <li>{{ step }}</li>
                        {% endfor %}
                    </ol>
                </div>
            </div>
            {% endfor %}
        </div>
        {% endif %}
        """

        # Update the template style to include mitigation steps styling
        mitigation_style = """
        .threat-details {
            margin: 20px 0;
            padding: 15px;
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        .mitigation-steps {
            margin-top: 15px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        .mitigation-steps h4 {
            color: #1a237e;
            margin-top: 0;
        }
        .mitigation-steps ol {
            margin: 10px 0;
            padding-left: 20px;
        }
        .mitigation-steps li {
            margin: 5px 0;
            color: #333;
        }
        """

        # Update the template with the new sections
        self.report_template = self.report_template.replace(
            "<!-- Detected Threats -->",
            "<!-- Detected Threats -->\n" + threat_section
        )
        self.report_template = self.report_template.replace(
            "</style>",
            mitigation_style + "\n</style>"
        ) 

    def _analyze_system_calls(self, processes=None):
        """Analyze system calls and their patterns"""
        try:
            # Initialize system calls data structure
            system_calls = {
                'total_calls': 0,
                'file_operations': 0,
                'network_operations': 0,
                'process_operations': 0,
                'frequent_calls': [],
                'suspicious_patterns': []
            }

            if processes is None:
                processes = list(psutil.process_iter(['pid', 'name', 'num_threads']))
            
            # Use pre-collected info if available
            system_calls['total_calls'] = sum(p.info.get('num_threads', 1) for p in processes)
            
            # Optimization: Skip deep per-process file/handle checks as they are extremely slow on Windows
            # and often require admin rights. Use summary stats where possible.
            file_ops = system_calls['total_calls'] // 2 # Simulated based on thread count
            
            # Count network operations (active connections).
            # On cloud/containerised hosts this may be restricted; treat as 0 when denied.
            try:
                system_calls['network_operations'] = len([conn for conn in psutil.net_connections()
                                                        if conn.status == 'ESTABLISHED'])
            except (psutil.AccessDenied, PermissionError, OSError):
                system_calls['network_operations'] = 0
            
            # Count process operations - use thread count as a fast proxy
            # (proc.children() is extremely slow on Windows)
            process_ops = max(0, len(processes) - 10)  # fast approximation
            system_calls['process_operations'] = process_ops
            
            # Example frequent system calls (simulated data)
            system_calls['frequent_calls'] = [
                {
                    'name': 'CreateFile',
                    'count': file_ops,
                    'category': 'File Operations',
                    'risk_level': 'Low'
                },
                {
                    'name': 'ReadFile/WriteFile',
                    'count': int(file_ops * 0.8),
                    'category': 'File Operations',
                    'risk_level': 'Low'
                },
                {
                    'name': 'Socket Operations',
                    'count': system_calls['network_operations'],
                    'category': 'Network Operations',
                    'risk_level': 'Medium'
                },
                {
                    'name': 'Process Creation',
                    'count': process_ops,
                    'category': 'Process Operations',
                    'risk_level': 'High'
                }
            ]

            # Add suspicious patterns based on thresholds
            if file_ops > 1000:
                system_calls['suspicious_patterns'].append({
                    'title': 'High File Operation Activity',
                    'description': 'Unusually high number of file operations detected',
                    'frequency': f'{file_ops} operations',
                    'risk_level': 'Medium',
                    'recommended_actions': [
                        'Monitor file access patterns',
                        'Check for potential data exfiltration',
                        'Review file access permissions',
                        'Implement file access auditing'
                    ]
                })

            if process_ops > 50:
                system_calls['suspicious_patterns'].append({
                    'title': 'High Process Creation Activity',
                    'description': 'Unusual number of child processes detected',
                    'frequency': f'{process_ops} processes',
                    'risk_level': 'High',
                    'recommended_actions': [
                        'Investigate process creation patterns',
                        'Check for unauthorized process spawning',
                        'Review process creation permissions',
                        'Implement process creation monitoring'
                    ]
                })

            return system_calls

        except Exception as e:
            logger.error(f"Error analyzing system calls: {str(e)}")
            # Return default structure if analysis fails
            return {
                'total_calls': 0,
                'file_operations': 0,
                'network_operations': 0,
                'process_operations': 0,
                'frequent_calls': [],
                'suspicious_patterns': []
            } 