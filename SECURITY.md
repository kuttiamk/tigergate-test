# 🔒 Security Policy — TigerGate CNAPP Target Simulator

## ⚠️ Important Disclaimer

This repository contains **intentionally vulnerable code, IaC, and configurations**.  
It is designed exclusively for CNAPP platform testing and security education.

## Acceptable Use

✅ **Allowed**
- Testing CNAPP platform detection capabilities (e.g., TigerGate)
- Security education and research in isolated lab environments
- Running local SAST/DAST/IaC scanners against this repository
- Demonstrating vulnerability classes for training purposes

❌ **Prohibited**
- Deploying any file from this repository in a production environment
- Using credentials, keys, or configurations from this repository against real infrastructure
- Sharing scanner results externally without appropriate disclosure controls

## Responsible Disclosure

If you discover a genuine vulnerability in the **testing framework itself** (not the intentional ones), please report it responsibly:

1. **Do NOT open a public GitHub issue** for security problems
2. Email: `security@tigergate-internal.example.com`
3. Include: description, reproduction steps, and potential impact
4. We will acknowledge within 48 hours

## Fake Credentials Notice

All secrets in this repository (AWS keys, JWT tokens, API keys, database passwords) are:
- Fake, non-functional test strings
- Designed to trigger scanner detections
- Clearly marked with comments like `# BAD:` or `🔴 VULN:`

They **cannot** be used to access any real infrastructure.

## License

This project is licensed under the MIT License. See `LICENSE` for details.
