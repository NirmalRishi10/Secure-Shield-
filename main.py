from flask import Flask, request, render_template, jsonify
import re
import tldextract
import requests

app = Flask(__name__)

# Your VirusTotal API key
VIRUSTOTAL_API_KEY = '9b60748bbd51bb738e224856477add6c256944bd9bca04165774747fb0a4d01d'

# List of suspicious substrings commonly found in phishing URLs
SUSPICIOUS_SUBSTRINGS = ['login', 'update', 'verify', 'account', 'security', 'bank', 'signin', 'suspend']

def is_suspicious_length(url):
    return len(url) > 100

def contains_suspicious_substrings(url):
    return any(substring in url.lower() for substring in SUSPICIOUS_SUBSTRINGS)

def is_ip_address(url):
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    return bool(ip_pattern.search(url))

def is_misleading_domain(url):
    domain = tldextract.extract(url).domain
    return len(domain) < 2 or re.search(r'[^\w\.-]', domain)

def check_url_virustotal(url):
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url}', headers=headers)
    if response.status_code == 200:
        result = response.json()
        if result['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            return "Suspicious: Detected by VirusTotal."
    return None

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():
    url = request.form['url']

    result = {
        'heuristic': None,
        'virustotal': None
    }

    if is_suspicious_length(url):
        result['heuristic'] = "Suspicious: URL length is too long."
    elif contains_suspicious_substrings(url):
        result['heuristic'] = "Suspicious: URL contains common phishing keywords."
    elif is_ip_address(url):
        result['heuristic'] = "Suspicious: URL contains an IP address."
    elif is_misleading_domain(url):
        result['heuristic'] = "Suspicious: Domain seems misleading or has unusual characters."
    else:
        result['heuristic'] = "URL seems safe."

    virustotal_result = check_url_virustotal(url)
    if virustotal_result:
        result['virustotal'] = virustotal_result
    else:
        result['virustotal'] = "VirusTotal analysis indicates no immediate threat."

    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
