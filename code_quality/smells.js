// Code Smell: usage of var and global scoping
var x = 10;
var myGlobalVar = "do not use";

function doAction(callback) {
    // Code Smell: Callback Hell (Pyramid of Doom)
    setTimeout(function () {
        setTimeout(function () {
            setTimeout(function () {
                var y = 20; // Variable shadowing implicitly
                if (x === 10) {
                    console.log("Deep inside");
                    // Code Smell: usage of eval
                    eval("console.log('Evaluated code')");
                }
                callback();
            }, 100);
        }, 100);
    }, 100);
}

function insecureCrypto() {
    // Code Smell: Insecure randomness
    var secret = Math.random();
    return secret;
}

// /* Code Smell: massive commented out code */
// function disabledFunction() {
//    var test = "dead functionality";
//    return test;
// }
