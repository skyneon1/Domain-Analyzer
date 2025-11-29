#!/usr/bin/env python3
"""
Extracted VulnerabilityScanner class for Vercel serverless functions
"""
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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class VulnerabilityScanner:
    def __init__(self):
        # Try multiple paths for model file (Vercel deployment vs local)
        self.possible_paths = [
            os.path.join(os.path.dirname(__file__), 'model.pkl'),  # scan-service/model.pkl
            os.path.join(os.path.dirname(__file__), '..', 'api', 'model.pkl'),  # api/model.pkl
            os.path.join(os.path.dirname(os.path.dirname(__file__)), 'api', 'model.pkl'),  # alternative path
        ]
        
        self.model_path = None
        for path in self.possible_paths:
            abs_path = os.path.abspath(path)
            if os.path.exists(abs_path):
                self.model_path = abs_path
                break
        
        self.model = None
        self.load_model()
    
    def load_model(self):
        """Load the trained vulnerability detection model"""
        try:
            if self.model_path and os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                print(f"Model loaded successfully from {self.model_path}")
            else:
                print(f"Model file not found. Searched paths: {[os.path.abspath(p) for p in self.possible_paths]}")
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
                'endpoints': endpoints[:50],
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
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            if severity == 'High':
                base_score -= 15
            elif severity == 'Medium':
                base_score -= 8
            elif severity == 'Low':
                base_score -= 3
        
        security_headers = crawl_data.get('security_headers', {})
        missing_headers = 0
        for header in ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection']:
            if not security_headers.get(header):
                missing_headers += 1
        
        base_score -= missing_headers * 5
        
        if crawl_data.get('url', '').startswith('http://'):
            base_score -= 20
        
        if crawl_data.get('server') or crawl_data.get('powered_by'):
            base_score -= 5
        
        return max(0.0, min(100.0, base_score))

    def analyze_vulnerabilities(self, crawl_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze the crawled data for potential vulnerabilities"""
        vulnerabilities = []
        
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
        
        if crawl_data.get('server') or crawl_data.get('powered_by'):
            vulnerabilities.append({
                'type': 'Information Disclosure',
                'severity': 'Low',
                'description': f'Server information exposed: {crawl_data.get("server", "")} {crawl_data.get("powered_by", "")}',
                'recommendation': 'Remove or obfuscate server information headers'
            })
        
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
        
        for form in forms:
            for input_field in form.get('inputs', []):
                if input_field.get('type') in ['text', 'textarea'] and not input_field.get('required'):
                    vulnerabilities.append({
                        'type': 'Potential XSS',
                        'severity': 'Medium',
                        'description': f'Unvalidated input field: {input_field.get("name", "unknown")}',
                        'recommendation': 'Implement proper input validation and sanitization'
                    })
        
        if crawl_data.get('url', '').startswith('http://'):
            vulnerabilities.append({
                'type': 'Insecure Protocol',
                'severity': 'High',
                'description': 'Website is served over HTTP instead of HTTPS',
                'recommendation': 'Implement HTTPS and redirect all HTTP traffic'
            })
        
        ml_predictions = []
        if self.model:
            try:
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
            features.append(len(crawl_data.get('endpoints', [])))
            features.append(len(crawl_data.get('forms', [])))
            features.append(len(crawl_data.get('scripts', [])))
            features.append(crawl_data.get('content_length', 0))
            
            security_headers = crawl_data.get('security_headers', {})
            features.append(1 if security_headers.get('X-Frame-Options') else 0)
            features.append(1 if security_headers.get('X-Content-Type-Options') else 0)
            features.append(1 if security_headers.get('X-XSS-Protection') else 0)
            features.append(1 if security_headers.get('Strict-Transport-Security') else 0)
            features.append(1 if security_headers.get('Content-Security-Policy') else 0)
            features.append(1 if security_headers.get('Referrer-Policy') else 0)
            
            forms = crawl_data.get('forms', [])
            post_forms = len([f for f in forms if f.get('method', '').upper() == 'POST'])
            features.append(post_forms)
            
            total_inputs = sum(len(f.get('inputs', [])) for f in forms)
            features.append(total_inputs)
            
            meta_tags = crawl_data.get('meta_tags', [])
            features.append(len(meta_tags))
            
            features.append(1 if crawl_data.get('server') else 0)
            features.append(1 if crawl_data.get('powered_by') else 0)
            
            url = crawl_data.get('url', '')
            features.append(1 if url.startswith('https://') else 0)
            features.append(1 if url.startswith('http://') else 0)
            
            status_code = crawl_data.get('status_code', 0)
            features.append(1 if status_code == 200 else 0)
            features.append(1 if status_code >= 400 else 0)
            features.append(1 if status_code >= 500 else 0)
            
            features.append(1 if crawl_data.get('content_length', 0) > 10000 else 0)
            features.append(1 if crawl_data.get('content_length', 0) > 50000 else 0)
            
            features.append(1 if any('csrf' in str(f).lower() for f in forms) else 0)
            features.append(1 if any('token' in str(f).lower() for f in forms) else 0)
            features.append(1 if any('captcha' in str(f).lower() for f in forms) else 0)
            
            while len(features) < 41:
                features.append(0.0)
            
            return features[:41]
            
        except Exception as e:
            print(f"Feature extraction error: {e}")
            return [0.0] * 41

    def scan_domain(self, domain: str) -> Dict[str, Any]:
        """Complete vulnerability scan for a domain"""
        try:
            crawl_data = self.crawl_website(domain)
            analysis = self.analyze_vulnerabilities(crawl_data)
            
            result = {
                'domain': domain,
                'scan_timestamp': pd.Timestamp.now().isoformat(),
                'crawl_data': crawl_data,
                'vulnerability_analysis': analysis,
                'status': 'completed'
            }
            
            return result
            
        except Exception as e:
            return {
                'domain': domain,
                'scan_timestamp': pd.Timestamp.now().isoformat(),
                'error': str(e),
                'traceback': traceback.format_exc(),
                'status': 'failed'
            }

