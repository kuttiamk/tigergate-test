const { exec } = require('child_process');

exports.handler = async (event) => {
    // Command Injection via Lambda input
    const command = event.command || "echo 'Hello World'";
    return new Promise((resolve, reject) => {
        exec(command, (error, stdout, stderr) => {
            if (error) {
                reject(error);
            }
            resolve(stdout);
        });
    });
};
