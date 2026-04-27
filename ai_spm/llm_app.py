# =============================================================================
# ai_spm/llm_app.py - TigerGate CNAPP Test: AI Security Posture Management
# =============================================================================
# PURPOSE: Demonstrates AI Security / LLM vulnerabilities (OWASP Top 10 for LLMs)
#
# TIGERGATE AI-SPM DETECTIONS MATCHING OWASP LLM V1.1:
#   LLM01: Prompt Injection
#   LLM06: Sensitive Information Disclosure
#   LLM08: Vector Database Authorization Bypass
# =============================================================================
import os
import sqlite3
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# 🔴 VULN: Hardcoded LLM API key
OPENAI_API_KEY = "sk-proj-dummyopenaiapikey1234567"

@app.route('/ask', methods=['POST'])
def chat():
    user_input = request.json.get('prompt')

    # 🔴 VULN: LLM01 - Prompt Injection. User input directly concatenated to system prompt.
    prompt = f"You are a helpful AI assistant for MegaCorp. Answer the user: {user_input}"
    
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }
    
    data = {"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": prompt}]}
    
    # Send directly to the LLM (No input sanitization via guardrails)
    response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=data)
    
    if response.status_code == 200:
        bot_response = response.json()['choices'][0]['message']['content']
        # 🔴 VULN: LLM02 - Insecure Output Handling. If the LLM returns HTML/JS, it goes straight to the client.
        return jsonify({"response": bot_response})
    
    return jsonify({"error": "Failed"}), 500

@app.route('/agent', methods=['POST'])
def ai_agent():
    """
    Simulates an LLM agent that has access to local functions.
    """
    command = request.json.get('command')
    
    # 🔴 VULN: LLM08 - AI Agent RCE / Insecure Plugin Design
    # The agent determines it needs to run a system command and we just eval/exec it!
    if "execute" in command:
        shell_cmd = command.split("execute ")[1]
        out = os.popen(shell_cmd).read() # 🔴 The AI can run 'rm -rf' or 'curl malware' on the host
        return jsonify({"agent_result": out})

    return jsonify({"status": "no action"})

if __name__ == '__main__':
    app.run(port=8080)
