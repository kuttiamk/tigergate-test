const express = require('express');
const app = express();
const serialize = require('node-serialize');

app.use(express.json());

// Advanced SAST / SCA Vulnerability: Insecure Deserialization via node-serialize
// Payload allowing direct IIFE execution bypassing standard input validation
/* Example exploit pattern:
  {"rce":"_$$ND_FUNC$$_function (){require('child_process').exec('ls /', function(error, stdout, stderr) { console.log(stdout) });}()"}
*/

app.post('/import', (req, res) => {
    try {
        let rawData = req.body.profile;
        // The deserialize function evaluates embedded functions by design, yielding RCE natively.
        let userProfile = serialize.unserialize(rawData);
        res.json({ message: "Imported config", data: userProfile });
    } catch (e) {
        res.status(500).send("Error");
    }
});

app.listen(8081, () => console.log('Deserialization API Running'));
