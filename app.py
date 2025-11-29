#!/usr/bin/env python3
import sys
import os
import json
import requests
from bs4 import BeautifulSoup
import joblib
import pandas as pd
import numpy as np
from urllib.parse import urljoin, urlparse
import re
from typing import Dict, List, Any
import traceback
import warnings
import urllib3
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from dotenv import load_dotenv
import sqlite3
import datetime
import hashlib
import threading
import time
import schedule
import json
import base64
import io
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.graph_objs as go
import plotly.utils
from apscheduler.schedulers.background import BackgroundScheduler
from cryptography.fernet import Fernet
import pyotp
import qrcode
import os

load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

scheduler = BackgroundScheduler()
scheduler.start()

if not os.path.exists('encryption.key'):
    key = Fernet.generate_key()
    with open('encryption.key', 'wb') as f:
        f.write(key)
else:
    with open('encryption.key', 'rb') as f:
        key = f.read()

cipher_suite = Fernet(key)

def init_db():
    """Initialize SQLite database for storing scan history"""
    conn = sqlite3.connect('scan_history.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            scan_timestamp TEXT NOT NULL,
            vulnerabilities_count INTEGER,
            high_severity INTEGER,
            medium_severity INTEGER,
            low_severity INTEGER,
            security_score REAL,
            ml_prediction TEXT,
            ml_confidence REAL,
            scan_data TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerability_trends (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            vulnerability_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            resolved BOOLEAN DEFAULT FALSE,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scheduled_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            schedule_type TEXT NOT NULL,
            schedule_value TEXT NOT NULL,
            last_run TEXT,
            next_run TEXT,
            active BOOLEAN DEFAULT TRUE,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerability_remediation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            vulnerability_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT DEFAULT 'open',
            assigned_to TEXT,
            due_date TEXT,
            resolution_notes TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_intelligence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_type TEXT NOT NULL,
            threat_source TEXT NOT NULL,
            threat_data TEXT NOT NULL,
            severity TEXT NOT NULL,
            affected_domains TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_benchmarks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            benchmark_type TEXT NOT NULL,
            score REAL NOT NULL,
            max_score REAL NOT NULL,
            details TEXT,
            scan_date TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

init_db()

class VulnerabilityScanner:
    def __init__(self):
        backend_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.join(backend_dir, 'model.pkl')
        self.model_path = os.path.abspath(model_path)
        self.model = None
        self.load_model()
    
    def load_model(self):
        """Load the trained vulnerability detection model"""
        try:
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                print(f"Model loaded successfully from {self.model_path}")
            else:
                print(f"Model file not found at {self.model_path}")
                self.model = None
        except Exception as e:
            print(f"Error loading model: {e}")
            self.model = None
    
    def crawl_website(self, url: str) -> Dict[str, Any]:
        """Crawl a website and extract security-relevant information"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            endpoints = []
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('/') or href.startswith('http'):
                    endpoints.append(href)
            
            forms = []
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET'),
                    'inputs': []
                }
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_data = {
                        'type': input_tag.get('type', input_tag.name),
                        'name': input_tag.get('name', ''),
                        'id': input_tag.get('id', ''),
                        'required': input_tag.get('required') is not None
                    }
                    form_data['inputs'].append(input_data)
                forms.append(form_data)
            
            scripts = []
            for script in soup.find_all('script'):
                src = script.get('src', '')
                if src:
                    scripts.append(src)
            
            meta_tags = []
            for meta in soup.find_all('meta'):
                meta_data = {
                    'name': meta.get('name', ''),
                    'content': meta.get('content', ''),
                    'http-equiv': meta.get('http-equiv', '')
                }
                meta_tags.append(meta_data)
            
            security_headers = {
                'X-Frame-Options': response.headers.get('X-Frame-Options', ''),
                'X-Content-Type-Options': response.headers.get('X-Content-Type-Options', ''),
                'X-XSS-Protection': response.headers.get('X-XSS-Protection', ''),
                'Strict-Transport-Security': response.headers.get('Strict-Transport-Security', ''),
                'Content-Security-Policy': response.headers.get('Content-Security-Policy', ''),
                'Referrer-Policy': response.headers.get('Referrer-Policy', '')
            }
            
            return {
                'url': url,
                'status_code': response.status_code,
                'endpoints': endpoints[:50],  # Limit to first 50
                'forms': forms,
                'scripts': scripts,
                'meta_tags': meta_tags,
                'security_headers': security_headers,
                'content_length': len(response.text),
                'server': response.headers.get('Server', ''),
                'powered_by': response.headers.get('X-Powered-By', '')
            }
            
        except Exception as e:
            return {
                'url': url,
                'error': str(e),
                'status_code': None,
                'endpoints': [],
                'forms': [],
                'scripts': [],
                'meta_tags': [],
                'security_headers': {},
                'content_length': 0,
                'server': '',
                'powered_by': ''
            }
    
    def calculate_security_score(self, vulnerabilities: List[Dict], crawl_data: Dict[str, Any]) -> float:
        """Calculate overall security score (0-100)"""
        base_score = 100.0
        
        # Deduct points for vulnerabilities
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            if severity == 'High':
                base_score -= 15
            elif severity == 'Medium':
                base_score -= 8
            elif severity == 'Low':
                base_score -= 3
        
        # Deduct points for missing security headers
        security_headers = crawl_data.get('security_headers', {})
        missing_headers = 0
        for header in ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection']:
            if not security_headers.get(header):
                missing_headers += 1
        
        base_score -= missing_headers * 5
        
        # Deduct points for HTTP instead of HTTPS
        if crawl_data.get('url', '').startswith('http://'):
            base_score -= 20
        
        # Deduct points for exposed server information
        if crawl_data.get('server') or crawl_data.get('powered_by'):
            base_score -= 5
        
        return max(0.0, min(100.0, base_score))

    def analyze_vulnerabilities(self, crawl_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze the crawled data for potential vulnerabilities"""
        vulnerabilities = []
        
        # Check for missing security headers
        missing_headers = []
        if not crawl_data.get('security_headers', {}).get('X-Frame-Options'):
            missing_headers.append('X-Frame-Options')
        if not crawl_data.get('security_headers', {}).get('X-Content-Type-Options'):
            missing_headers.append('X-Content-Type-Options')
        if not crawl_data.get('security_headers', {}).get('X-XSS-Protection'):
            missing_headers.append('X-XSS-Protection')
        
        if missing_headers:
            vulnerabilities.append({
                'type': 'Missing Security Headers',
                'severity': 'Medium',
                'description': f'Missing security headers: {", ".join(missing_headers)}',
                'recommendation': 'Implement proper security headers to protect against common attacks'
            })
        
        # Check for exposed server information
        if crawl_data.get('server') or crawl_data.get('powered_by'):
            vulnerabilities.append({
                'type': 'Information Disclosure',
                'severity': 'Low',
                'description': f'Server information exposed: {crawl_data.get("server", "")} {crawl_data.get("powered_by", "")}',
                'recommendation': 'Remove or obfuscate server information headers'
            })
        
        # Check for forms without CSRF protection
        forms = crawl_data.get('forms', [])
        for form in forms:
            if form.get('method', '').upper() == 'POST':
                has_csrf = False
                for input_field in form.get('inputs', []):
                    if any(csrf_name in input_field.get('name', '').lower() for csrf_name in ['csrf', 'token', '_token']):
                        has_csrf = True
                        break
                
                if not has_csrf:
                    vulnerabilities.append({
                        'type': 'CSRF Vulnerability',
                        'severity': 'High',
                        'description': f'Form at {form.get("action", "unknown")} lacks CSRF protection',
                        'recommendation': 'Implement CSRF tokens for all POST forms'
                    })
        
        # Check for potential XSS in forms
        for form in forms:
            for input_field in form.get('inputs', []):
                if input_field.get('type') in ['text', 'textarea'] and not input_field.get('required'):
                    vulnerabilities.append({
                        'type': 'Potential XSS',
                        'severity': 'Medium',
                        'description': f'Unvalidated input field: {input_field.get("name", "unknown")}',
                        'recommendation': 'Implement proper input validation and sanitization'
                    })
        
        # Check for HTTP instead of HTTPS
        if crawl_data.get('url', '').startswith('http://'):
            vulnerabilities.append({
                'type': 'Insecure Protocol',
                'severity': 'High',
                'description': 'Website is served over HTTP instead of HTTPS',
                'recommendation': 'Implement HTTPS and redirect all HTTP traffic'
            })
        
        # Use ML model if available
        ml_predictions = []
        if self.model:
            try:
                # Create features for ML model
                features = self._extract_features(crawl_data)
                if features:
                    prediction = self.model.predict([features])[0]
                    probability = self.model.predict_proba([features])[0].max()
                    
                    ml_predictions.append({
                        'prediction': str(prediction),
                        'confidence': float(probability),
                        'features_used': len(features)
                    })
            except Exception as e:
                print(f"ML prediction error: {e}")
        
        # Calculate security score
        security_score = self.calculate_security_score(vulnerabilities, crawl_data)
        
        return {
            'vulnerabilities': vulnerabilities,
            'ml_predictions': ml_predictions,
            'security_score': security_score,
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'high_severity': len([v for v in vulnerabilities if v['severity'] == 'High']),
                'medium_severity': len([v for v in vulnerabilities if v['severity'] == 'Medium']),
                'low_severity': len([v for v in vulnerabilities if v['severity'] == 'Low'])
            }
        }
    
    def _extract_features(self, crawl_data: Dict[str, Any]) -> List[float]:
        """Extract features for ML model prediction"""
        try:
            features = []
            
            # Basic features
            features.append(len(crawl_data.get('endpoints', [])))
            features.append(len(crawl_data.get('forms', [])))
            features.append(len(crawl_data.get('scripts', [])))
            features.append(crawl_data.get('content_length', 0))
            
            # Security header features
            security_headers = crawl_data.get('security_headers', {})
            features.append(1 if security_headers.get('X-Frame-Options') else 0)
            features.append(1 if security_headers.get('X-Content-Type-Options') else 0)
            features.append(1 if security_headers.get('X-XSS-Protection') else 0)
            features.append(1 if security_headers.get('Strict-Transport-Security') else 0)
            features.append(1 if security_headers.get('Content-Security-Policy') else 0)
            features.append(1 if security_headers.get('Referrer-Policy') else 0)
            
            # Form analysis features
            forms = crawl_data.get('forms', [])
            post_forms = len([f for f in forms if f.get('method', '').upper() == 'POST'])
            features.append(post_forms)
            
            # Input field analysis
            total_inputs = sum(len(f.get('inputs', [])) for f in forms)
            features.append(total_inputs)
            
            # Meta tags analysis
            meta_tags = crawl_data.get('meta_tags', [])
            features.append(len(meta_tags))
            
            # Server information
            features.append(1 if crawl_data.get('server') else 0)
            features.append(1 if crawl_data.get('powered_by') else 0)
            
            # URL analysis
            url = crawl_data.get('url', '')
            features.append(1 if url.startswith('https://') else 0)
            features.append(1 if url.startswith('http://') else 0)
            
            # Status code analysis
            status_code = crawl_data.get('status_code', 0)
            features.append(1 if status_code == 200 else 0)
            features.append(1 if status_code >= 400 else 0)
            features.append(1 if status_code >= 500 else 0)
            
            # Content analysis
            features.append(1 if crawl_data.get('content_length', 0) > 10000 else 0)
            features.append(1 if crawl_data.get('content_length', 0) > 50000 else 0)
            
            # Additional security features
            features.append(1 if any('csrf' in str(f).lower() for f in forms) else 0)
            features.append(1 if any('token' in str(f).lower() for f in forms) else 0)
            features.append(1 if any('captcha' in str(f).lower() for f in forms) else 0)
            
            # Pad with zeros to match expected 41 features
            while len(features) < 41:
                features.append(0.0)
            
            return features[:41]  # Ensure we have exactly 41 features
            
        except Exception as e:
            print(f"Feature extraction error: {e}")
            return [0.0] * 41  # Return default features
    
    def save_scan_to_db(self, result: Dict[str, Any]):
        """Save scan result to database"""
        try:
            conn = sqlite3.connect('scan_history.db')
            cursor = conn.cursor()
            
            analysis = result.get('vulnerability_analysis', {})
            summary = analysis.get('summary', {})
            ml_predictions = analysis.get('ml_predictions', [])
            
            cursor.execute('''
                INSERT INTO scan_history 
                (domain, scan_timestamp, vulnerabilities_count, high_severity, medium_severity, 
                 low_severity, security_score, ml_prediction, ml_confidence, scan_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                result.get('domain'),
                result.get('scan_timestamp'),
                summary.get('total_vulnerabilities', 0),
                summary.get('high_severity', 0),
                summary.get('medium_severity', 0),
                summary.get('low_severity', 0),
                analysis.get('security_score', 0),
                ml_predictions[0].get('prediction', '') if ml_predictions else '',
                ml_predictions[0].get('confidence', 0) if ml_predictions else 0,
                json.dumps(result)
            ))
            
            # Save individual vulnerabilities for trend analysis
            vulnerabilities = analysis.get('vulnerabilities', [])
            for vuln in vulnerabilities:
                cursor.execute('''
                    INSERT INTO vulnerability_trends 
                    (domain, vulnerability_type, severity, scan_date)
                    VALUES (?, ?, ?, ?)
                ''', (
                    result.get('domain'),
                    vuln.get('type', ''),
                    vuln.get('severity', ''),
                    result.get('scan_timestamp')
                ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error saving to database: {e}")

    def scan_domain(self, domain: str) -> Dict[str, Any]:
        """Complete vulnerability scan for a domain"""
        try:
            # Crawl the website
            crawl_data = self.crawl_website(domain)
            
            # Analyze for vulnerabilities
            analysis = self.analyze_vulnerabilities(crawl_data)
            
            result = {
                'domain': domain,
                'scan_timestamp': pd.Timestamp.now().isoformat(),
                'crawl_data': crawl_data,
                'vulnerability_analysis': analysis,
                'status': 'completed'
            }
            
            # Save to database in background
            threading.Thread(target=self.save_scan_to_db, args=(result,)).start()
            
            # Emit real-time update via WebSocket
            socketio.emit('scan_completed', {
                'domain': domain,
                'security_score': analysis.get('security_score', 0),
                'vulnerabilities_count': analysis.get('summary', {}).get('total_vulnerabilities', 0),
                'timestamp': result.get('scan_timestamp')
            })
            
            return result
            
        except Exception as e:
            return {
                'domain': domain,
                'scan_timestamp': pd.Timestamp.now().isoformat(),
                'error': str(e),
                'traceback': traceback.format_exc(),
                'status': 'failed'
            }

# Initialize scanner
scanner = VulnerabilityScanner()

@app.route('/api/scan', methods=['POST'])
def scan_domain():
    """API endpoint to scan a domain for vulnerabilities"""
    try:
        data = request.get_json()
        domain = data.get('domain')
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        result = scanner.scan_domain(domain)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': scanner.model is not None
    })

@app.route('/api/history', methods=['GET'])
def get_scan_history():
    """Get scan history for a domain"""
    domain = request.args.get('domain')
    limit = int(request.args.get('limit', 10))
    
    try:
        conn = sqlite3.connect('scan_history.db')
        cursor = conn.cursor()
        
        if domain:
            cursor.execute('''
                SELECT * FROM scan_history 
                WHERE domain = ? 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (domain, limit))
        else:
            cursor.execute('''
                SELECT * FROM scan_history 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (limit,))
        
        rows = cursor.fetchall()
        columns = [description[0] for description in cursor.description]
        
        history = []
        for row in rows:
            history.append(dict(zip(columns, row)))
        
        conn.close()
        return jsonify({'history': history})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/trends', methods=['GET'])
def get_vulnerability_trends():
    """Get vulnerability trends for a domain"""
    domain = request.args.get('domain')
    days = int(request.args.get('days', 30))
    
    try:
        conn = sqlite3.connect('scan_history.db')
        cursor = conn.cursor()
        
        if domain:
            cursor.execute('''
                SELECT vulnerability_type, severity, COUNT(*) as count
                FROM vulnerability_trends 
                WHERE domain = ? AND scan_date >= datetime('now', '-{} days')
                GROUP BY vulnerability_type, severity
                ORDER BY count DESC
            '''.format(days), (domain,))
        else:
            cursor.execute('''
                SELECT vulnerability_type, severity, COUNT(*) as count
                FROM vulnerability_trends 
                WHERE scan_date >= datetime('now', '-{} days')
                GROUP BY vulnerability_type, severity
                ORDER BY count DESC
            '''.format(days))
        
        rows = cursor.fetchall()
        trends = []
        for row in rows:
            trends.append({
                'vulnerability_type': row[0],
                'severity': row[1],
                'count': row[2]
            })
        
        conn.close()
        return jsonify({'trends': trends})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/domains', methods=['GET'])
def get_scanned_domains():
    """Get list of all scanned domains"""
    try:
        conn = sqlite3.connect('scan_history.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT domain, COUNT(*) as scan_count, 
                   MAX(created_at) as last_scan,
                   AVG(security_score) as avg_score
            FROM scan_history 
            GROUP BY domain
            ORDER BY last_scan DESC
        ''')
        
        rows = cursor.fetchall()
        domains = []
        for row in rows:
            domains.append({
                'domain': row[0],
                'scan_count': row[1],
                'last_scan': row[2],
                'avg_score': round(row[3], 2) if row[3] else 0
            })
        
        conn.close()
        return jsonify({'domains': domains})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/<domain>', methods=['GET'])
def export_scan_report(domain):
    """Export scan report as JSON"""
    try:
        conn = sqlite3.connect('scan_history.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT scan_data FROM scan_history 
            WHERE domain = ? 
            ORDER BY created_at DESC 
            LIMIT 1
        ''', (domain,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            scan_data = json.loads(row[0])
            return jsonify(scan_data)
        else:
            return jsonify({'error': 'No scan data found for domain'}), 404
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard', methods=['GET'])
def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        conn = sqlite3.connect('scan_history.db')
        cursor = conn.cursor()
        
        # Total scans
        cursor.execute('SELECT COUNT(*) FROM scan_history')
        total_scans = cursor.fetchone()[0]
        
        # Unique domains
        cursor.execute('SELECT COUNT(DISTINCT domain) FROM scan_history')
        unique_domains = cursor.fetchone()[0]
        
        # Average security score
        cursor.execute('SELECT AVG(security_score) FROM scan_history')
        avg_score = cursor.fetchone()[0] or 0
        
        # Recent scans (last 7 days)
        cursor.execute('''
            SELECT COUNT(*) FROM scan_history 
            WHERE created_at >= datetime('now', '-7 days')
        ''')
        recent_scans = cursor.fetchone()[0]
        
        # Top vulnerability types
        cursor.execute('''
            SELECT vulnerability_type, COUNT(*) as count
            FROM vulnerability_trends 
            WHERE scan_date >= datetime('now', '-30 days')
            GROUP BY vulnerability_type
            ORDER BY count DESC
            LIMIT 5
        ''')
        top_vulns = cursor.fetchall()
        
        # Active scheduled scans
        cursor.execute('SELECT COUNT(*) FROM scheduled_scans WHERE active = 1')
        active_schedules = cursor.fetchone()[0]
        
        # Open vulnerabilities
        cursor.execute('SELECT COUNT(*) FROM vulnerability_remediation WHERE status = "open"')
        open_vulnerabilities = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'total_scans': total_scans,
            'unique_domains': unique_domains,
            'avg_security_score': round(avg_score, 2),
            'recent_scans': recent_scans,
            'active_schedules': active_schedules,
            'open_vulnerabilities': open_vulnerabilities,
            'top_vulnerabilities': [{'type': row[0], 'count': row[1]} for row in top_vulns]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/schedule', methods=['GET'])
def get_scheduled_scans():
    """Get all scheduled scans"""
    try:
        conn = sqlite3.connect('scan_history.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM scheduled_scans 
            ORDER BY created_at DESC
        ''')
        
        rows = cursor.fetchall()
        columns = [description[0] for description in cursor.description]
        
        schedules = []
        for row in rows:
            schedules.append(dict(zip(columns, row)))
        
        conn.close()
        return jsonify({'schedules': schedules})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/schedule', methods=['POST'])
def schedule_scan():
    """Schedule automated vulnerability scans"""
    try:
        data = request.get_json()
        domain = data.get('domain')
        schedule_type = data.get('schedule_type')  # daily, weekly, monthly
        schedule_value = data.get('schedule_value')  # time or day
        
        if not all([domain, schedule_type, schedule_value]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        conn = sqlite3.connect('scan_history.db')
        cursor = conn.cursor()
        
        # Calculate next run time
        next_run = datetime.datetime.now().isoformat()
        if schedule_type == 'daily' and ':' in schedule_value:
            try:
                hour, minute = map(int, schedule_value.split(':'))
                next_run = datetime.datetime.now().replace(hour=hour, minute=minute, second=0, microsecond=0)
                if next_run < datetime.datetime.now():
                    next_run += datetime.timedelta(days=1)
                next_run = next_run.isoformat()
            except:
                pass
        
        cursor.execute('''
            INSERT INTO scheduled_scans (domain, schedule_type, schedule_value, next_run)
            VALUES (?, ?, ?, ?)
        ''', (domain, schedule_type, schedule_value, next_run))
        
        conn.commit()
        conn.close()
        
        # Schedule the actual job
        if schedule_type == 'daily':
            scheduler.add_job(
                func=run_scheduled_scan,
                trigger='cron',
                hour=int(schedule_value.split(':')[0]),
                minute=int(schedule_value.split(':')[1]),
                args=[domain],
                id=f"daily_{domain}_{schedule_value}"
            )
        elif schedule_type == 'weekly':
            scheduler.add_job(
                func=run_scheduled_scan,
                trigger='cron',
                day_of_week=schedule_value,
                hour=9,
                args=[domain],
                id=f"weekly_{domain}_{schedule_value}"
            )
        
        return jsonify({'message': 'Scan scheduled successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def run_scheduled_scan(domain):
    """Run a scheduled scan"""
    try:
        result = scanner.scan_domain(domain)
        socketio.emit('scheduled_scan_completed', {
            'domain': domain,
            'result': result
        })
    except Exception as e:
        socketio.emit('scheduled_scan_failed', {
            'domain': domain,
            'error': str(e)
        })

@app.route('/api/remediation', methods=['GET'])
def get_remediation_tasks():
    """Get vulnerability remediation tasks"""
    try:
        conn = sqlite3.connect('scan_history.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM vulnerability_remediation 
            ORDER BY created_at DESC
        ''')
        
        rows = cursor.fetchall()
        columns = [description[0] for description in cursor.description]
        
        tasks = []
        for row in rows:
            tasks.append(dict(zip(columns, row)))
        
        conn.close()
        return jsonify({'tasks': tasks})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/remediation', methods=['POST'])
def create_remediation_task():
    """Create a vulnerability remediation task"""
    try:
        data = request.get_json()
        
        conn = sqlite3.connect('scan_history.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO vulnerability_remediation 
            (domain, vulnerability_type, severity, assigned_to, due_date, resolution_notes)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            data.get('domain'),
            data.get('vulnerability_type'),
            data.get('severity'),
            data.get('assigned_to'),
            data.get('due_date'),
            data.get('resolution_notes', '')
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Remediation task created successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/remediation/<int:task_id>', methods=['PUT'])
def update_remediation_task(task_id):
    """Update a vulnerability remediation task"""
    try:
        data = request.get_json()
        
        conn = sqlite3.connect('scan_history.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE vulnerability_remediation 
            SET status = ?, resolution_notes = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (data.get('status'), data.get('resolution_notes'), task_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Task updated successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat-intelligence', methods=['GET'])
def get_threat_intelligence():
    """Get threat intelligence data"""
    try:
        conn = sqlite3.connect('scan_history.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM threat_intelligence 
            ORDER BY created_at DESC
            LIMIT 50
        ''')
        
        rows = cursor.fetchall()
        columns = [description[0] for description in cursor.description]
        
        threats = []
        for row in rows:
            threats.append(dict(zip(columns, row)))
        
        conn.close()
        return jsonify({'threats': threats})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat-intelligence', methods=['POST'])
def add_threat_intelligence():
    """Add threat intelligence data"""
    try:
        data = request.get_json()
        
        conn = sqlite3.connect('scan_history.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO threat_intelligence 
            (threat_type, threat_source, threat_data, severity, affected_domains)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            data.get('threat_type'),
            data.get('threat_source'),
            data.get('threat_data'),
            data.get('severity'),
            data.get('affected_domains', '')
        ))
        
        conn.commit()
        conn.close()
        
        # Emit real-time threat alert
        socketio.emit('threat_alert', {
            'threat_type': data.get('threat_type'),
            'severity': data.get('severity'),
            'affected_domains': data.get('affected_domains', '')
        })
        
        return jsonify({'message': 'Threat intelligence added successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/benchmarks', methods=['GET'])
def get_security_benchmarks():
    """Get security benchmark scores"""
    try:
        domain = request.args.get('domain')
        
        conn = sqlite3.connect('scan_history.db')
        cursor = conn.cursor()
        
        if domain:
            cursor.execute('''
                SELECT * FROM security_benchmarks 
                WHERE domain = ?
                ORDER BY scan_date DESC
            ''', (domain,))
        else:
            cursor.execute('''
                SELECT * FROM security_benchmarks 
                ORDER BY scan_date DESC
                LIMIT 100
            ''')
        
        rows = cursor.fetchall()
        columns = [description[0] for description in cursor.description]
        
        benchmarks = []
        for row in rows:
            benchmarks.append(dict(zip(columns, row)))
        
        conn.close()
        return jsonify({'benchmarks': benchmarks})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics/charts', methods=['GET'])
def get_analytics_charts():
    """Get analytics data for charts"""
    try:
        chart_type = request.args.get('type', 'security_trends')
        days = int(request.args.get('days', 30))
        
        conn = sqlite3.connect('scan_history.db')
        cursor = conn.cursor()
        
        if chart_type == 'security_trends':
            cursor.execute('''
                SELECT DATE(scan_timestamp) as date, AVG(security_score) as avg_score
                FROM scan_history 
                WHERE scan_timestamp >= datetime('now', '-{} days')
                GROUP BY DATE(scan_timestamp)
                ORDER BY date
            '''.format(days))
            
            data = cursor.fetchall()
            chart_data = {
                'labels': [row[0] for row in data],
                'datasets': [{
                    'label': 'Security Score',
                    'data': [row[1] for row in data],
                    'borderColor': 'rgb(75, 192, 192)',
                    'backgroundColor': 'rgba(75, 192, 192, 0.2)'
                }]
            }
            
        elif chart_type == 'vulnerability_distribution':
            cursor.execute('''
                SELECT severity, COUNT(*) as count
                FROM vulnerability_trends 
                WHERE scan_date >= datetime('now', '-{} days')
                GROUP BY severity
            '''.format(days))
            
            data = cursor.fetchall()
            chart_data = {
                'labels': [row[0] for row in data],
                'datasets': [{
                    'label': 'Vulnerabilities',
                    'data': [row[1] for row in data],
                    'backgroundColor': [
                        'rgba(255, 99, 132, 0.8)',
                        'rgba(255, 159, 64, 0.8)',
                        'rgba(255, 205, 86, 0.8)',
                        'rgba(75, 192, 192, 0.8)'
                    ]
                }]
            }
        
        conn.close()
        return jsonify(chart_data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/2fa/generate', methods=['POST'])
def generate_2fa():
    """Generate 2FA secret and QR code"""
    try:
        data = request.get_json()
        user_email = data.get('email', 'user@example.com')
        
        # Generate secret
        secret = pyotp.random_base32()
        
        # Generate QR code
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user_email,
            issuer_name="Vulnerability Scanner"
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return jsonify({
            'secret': secret,
            'qr_code': f"data:image/png;base64,{img_str}",
            'uri': totp_uri
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/2fa/verify', methods=['POST'])
def verify_2fa():
    """Verify 2FA token"""
    try:
        data = request.get_json()
        secret = data.get('secret')
        token = data.get('token')
        
        totp = pyotp.TOTP(secret)
        is_valid = totp.verify(token)
        
        return jsonify({'valid': is_valid})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# WebSocket events
@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('connected', {'message': 'Connected to vulnerability scanner'})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('join_dashboard')
def handle_join_dashboard():
    print('Client joined dashboard')
    emit('dashboard_joined', {'message': 'Joined dashboard updates'})

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
