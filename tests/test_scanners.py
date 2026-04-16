import pytest
import time
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from plugins.xss_scanner_plugin import XSSScannerPlugin
from plugins.lfi_scanner_plugin import LFIScannerPlugin
from plugins.ssrf_scanner_plugin import SSRFScannerPlugin
from core.models import Finding

# Mock Server para simular vulnerabilidades
class MockVulnerabilityServer(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return # Silenciar logs de request

    def do_GET(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        
        # Simular XSS refletido
        if parsed_path.path == '/xss':
            q = params.get('q', [''])[0]
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(f"<html><body>Result: {q}</body></html>".encode())
            return

        # Simular LFI
        if parsed_path.path == '/lfi':
            file = params.get('file', [''])[0]
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            if "/etc/passwd" in file:
                self.wfile.write(b"root:x:0:0:root:/root:/bin/bash")
            elif "win.ini" in file.lower():
                self.wfile.write(b"[extensions]\nbitmaps=yes")
            else:
                self.wfile.write(b"File not found")
            return

        # Simular SSRF para AWS
        if parsed_path.path == '/ssrf':
            url = params.get('url', [''])[0]
            if "169.254.169.254" in url:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ami-id\ninstance-id")
                return

        self.send_response(404)
        self.end_headers()

@pytest.fixture(scope="module")
def mock_server():
    server = HTTPServer(('127.0.0.1', 0), MockVulnerabilityServer)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()

def test_xss_scanner_detection(mock_server):
    target_url = f"{mock_server}/xss"
    scanner = XSSScannerPlugin(config={'use_tor': False})
    
    # Criar contexto simulando descoberta previa do crawler
    context = {
        'discoveries': {
            'endpoints': [
                {
                    'url': target_url,
                    'method': 'GET',
                    'params': {'q': 'test'}
                }
            ]
        }
    }
    
    result = scanner.execute(target_url, context)
    assert result.success is True
    # Deve encontrar pelo menos um hit de XSS
    vulns = result.data.get('vulnerabilities', [])
    assert len(vulns) > 0
    assert any("Cross-Site Scripting" in v['name'] for v in vulns)

def test_lfi_scanner_detection(mock_server):
    target_url = f"{mock_server}/lfi"
    scanner = LFIScannerPlugin(config={'use_tor': False})
    
    context = {
        'discoveries': {
            'endpoints': [
                {
                    'url': target_url,
                    'method': 'GET',
                    'params': {'file': 'test.txt'}
                }
            ]
        }
    }
    
    result = scanner.execute(target_url, context)
    assert result.success is True
    vulns = result.data.get('vulnerabilities', [])
    assert len(vulns) > 0
    assert any("Local File Inclusion" in v['name'] for v in vulns)

def test_ssrf_scanner_detection(mock_server):
    target_url = f"{mock_server}/ssrf"
    scanner = SSRFScannerPlugin(config={'use_tor': False})
    
    context = {
        'discoveries': {
            'endpoints': [
                {
                    'url': target_url,
                    'method': 'GET',
                    'params': {'url': 'http://google.com'}
                }
            ]
        }
    }
    
    result = scanner.execute(target_url, context)
    assert result.success is True
    vulns = result.data.get('vulnerabilities', [])
    assert len(vulns) > 0
    assert any("SSRF" in v['name'] for v in vulns)
