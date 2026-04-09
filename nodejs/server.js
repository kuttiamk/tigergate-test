const express = require('express');
const app = express();

// Vulnerability 1: Hardcoded Secrets
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// Vulnerability 2: Code Injection / Eval
app.get('/evaluate', (req, res) => {
    const code = req.query.code;
    // Flaw: Executing arbitrary JS code supplied by user
    const result = eval(code);
    res.send('Result: ' + result);
});

// Vulnerability 3: Insecure Deserialization
app.post('/deserialize', (req, res) => {
    const serializedData = req.body.data;
    // Flaw: Unsafe JSON mapping or parsing mechanism missing proper validation
    // Node-serialize or similar could be imported to show explicit flaw
    const obj = JSON.parse(serializedData); // Weak generic demonstration without dependencies
    res.send(obj);
});

app.listen(3000, () => console.log('Server running on port 3000'));
