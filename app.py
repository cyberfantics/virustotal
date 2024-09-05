from flask import Flask, request, render_template, jsonify
import requests
import os
import time

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Replace with your actual secret key

# Ensure the uploads directory exists
if not os.path.exists('uploads'):
    os.makedirs('uploads')

def upload_file_to_virustotal(api_key, file_path):
    headers = {
        "x-apikey": api_key
    }

    with open(file_path, "rb") as file_to_upload:
        # Upload the file to VirusTotal for scanning
        upload_url = 'https://www.virustotal.com/api/v3/files'
        response = requests.post(upload_url, headers=headers, files={"file": file_to_upload})

    if response.status_code != 200:
        return {"error": f"Error uploading file to VirusTotal. Response: {response.text}"}
    
    response_json = response.json()
    analysis_id = response_json.get('data', {}).get('id', None)

    if not analysis_id:
        return {"error": "Error: Unable to retrieve analysis ID."}

    # Poll for analysis results using the analysis ID
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    
    retries = 10  # Max retries
    while retries > 0:
        response = requests.get(analysis_url, headers=headers)
        report = response.json()

        if response.status_code != 200:
            return {"error": "Error retrieving report from VirusTotal"}
        
        status = report['data']['attributes']['status']
        if status == 'completed':
            return {"result": print_analysis_results_for_file(report, file_path)}
        
        time.sleep(10)
        retries -= 1
    
    return {"error": "Analysis took too long. Please try again later."}

def print_analysis_results_for_file(result, file_path):
    try:
        stats = result['data']['attributes']['stats']
        total = stats['malicious'] + stats['suspicious'] + stats['undetected'] + stats['harmless']
        file_info = result["data"]["attributes"]
        
        table = f"""
        <table>
            <tr><th class="key">File Info</th><th class="value">Details</th></tr>
            <tr><td class="key">File Size</td><td class="value">{result['meta']['file_info'].get('size', 'Unknown')} bytes</td></tr>
            <tr><td class="key">SHA256</td><td class="value">{result['meta']['file_info'].get('sha256', 'Unknown')}</td></tr>
            <tr><td class="key">MD5</td><td class="value">{result['meta']['file_info'].get('md5', 'Unknown')}</td></tr>
            <tr><td class="key">SHA1</td><td class="value">{result['meta']['file_info'].get('sha1', 'Unknown')}</td></tr>
            <tr><td class="key">File Name</td><td class="value">{file_path}</td></tr>
            <tr><td class="key">Malicious</td><td class="value">{stats['malicious']} antivirus programs detected the file as malicious.</td></tr>
            <tr><td class="key">Suspicious</td><td class="value">{stats['suspicious']} antivirus programs flagged the file as suspicious.</td></tr>
            <tr><td class="key">Non-Malicious</td><td class="value">{stats['undetected']} antivirus programs detected the file as non-malicious.</td></tr>
            <tr><td class="key">Harmless</td><td class="value">{stats['harmless']} antivirus programs detected the file as harmless.</td></tr>
            <tr><td class="key">Total Score</td><td class="value">{stats['malicious']}/{total} antivirus programs detected the file as harmful or suspicious.</td></tr>
        </table>
        """
        return table
    except KeyError:
        return "Incomplete data received from VirusTotal."

def print_analysis_results(report):
    try:
        analysis_stats = report["data"]["attributes"]["last_analysis_stats"]
        file_info = report["data"]["attributes"]
        
        # Extract relevant information
        size = file_info.get("size", "Unknown")
        sha256 = file_info.get("sha256", "Unknown")
        md5 = file_info.get("md5", "Unknown")
        sha1 = file_info.get("sha1", "Unknown")
        file_name = file_info.get("meaningful_name", "Unknown")
        
        # Analysis stats
        malicious_count = analysis_stats.get("malicious", 0)
        suspicious_count = analysis_stats.get("suspicious", 0)
        undetected_count = analysis_stats.get("undetected", 0)
        harmless_count = analysis_stats.get("harmless", 0)
        
        total_score = int(malicious_count) + int(suspicious_count)
        
        return f'''
            <table>
                <tr><th class="key">File Name</th><td class="value">{file_name}</td></tr>
                <tr><th class="key">File Size</th><td class="value">{size} bytes</td></tr>
                <tr><th class="key">SHA256</th><td class="value">{sha256}</td></tr>
                <tr><th class="key">MD5</th><td class="value">{md5}</td></tr>
                <tr><th class="key">SHA1</th><td class="value">{sha1}</td></tr>
                <tr><th class="key">Malicious</th><td class="value">{malicious_count} antivirus programs detected the file as malicious.</td></tr>
                <tr><th class="key">Suspicious</th><td class="value">{suspicious_count} antivirus programs flagged the file as suspicious.</td></tr>
                <tr><th class="key">Non-Malicious</th><td class="value">{undetected_count} antivirus programs detected the file as non-malicious.</td></tr>
                <tr><th class="key">Harmless</th><td class="value">{harmless_count} antivirus programs detected the file as harmless.</td></tr>
                <tr><th class="key">Total Score</th><td class="value">{total_score} antivirus programs detected the file as harmful or suspicious.</td></tr>
            </table>
        '''
    except KeyError:
        return "Incomplete data received from VirusTotal."

def lookup_hash_on_virustotal(api_key, file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers)
        analysis_result = response.json()
    
        if 'data' in analysis_result:
            return {"result": print_analysis_results(analysis_result)}
        else:
            return {"error": "No data found for the provided hash."}

    except KeyError:
        return {"error": "Error retrieving report from VirusTotal"}
    except Exception as e:
        return {"error": f"An error occurred: {e}"}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    api_key = open("vt-api.txt", "r").read().strip()

    if 'file' not in request.files:
        return jsonify({"error": "No file part"})

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No selected file"})

    if file:
        file_path = os.path.join("uploads", file.filename)
        file.save(file_path)
        result = upload_file_to_virustotal(api_key, file_path)
        return jsonify(result)

@app.route('/hash', methods=['POST'])
def check_hash():
    api_key = open("vt-api.txt", "r").read().strip()
    file_hash = request.form['file_hash']
    result = lookup_hash_on_virustotal(api_key, file_hash)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)
