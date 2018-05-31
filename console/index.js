const DlcOracle = require('dlc-oracle-nodejs').DlcOracle;
const randomBytes = require('crypto').randomBytes;
const readline = require('readline');
const fs = require('fs')
const path = require('path')
function main() {
    var privateKey;
    var keyFile = path.join(__dirname,"privkey.hex");
    if(fs.existsSync(keyFile)) {
        privateKey = fs.readFileSync(keyFile);
    } else {
        privateKey = randomBytes(32);
        fs.writeFileSync(keyFile, privateKey);
    }

    var publicKey = DlcOracle.publicKeyFromPrivateKey(privateKey);

    console.log("Oracle Public Key: ",publicKey.toString('hex'));

    doSignLoop(privateKey, publicKey);
}

function doSignLoop(privateKey, publicKey) {
    // Generate one-time signing private scalar
    let privPoint = DlcOracle.generateOneTimeSigningKey()
    // Print out the R-Point (public key to the private scalar)
    rPoint = DlcOracle.publicKeyFromPrivateKey(privPoint)
    console.log("R-Point for next publication: ", rPoint.toString('hex'))

    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    
    rl.question('Enter number to publish (-1 to exit): ', (answer) => {
        i = parseInt(answer);
        rl.close();
        if(i != -1)
        {
            message = DlcOracle.generateNumericMessage(i);
            sig = DlcOracle.computeSignature(privateKey,privPoint,message)
            console.log("Signature: ", sig.toString('hex'));

            sgFromSig = DlcOracle.publicKeyFromPrivateKey(sig);
            console.log("Compute sG from Signature:", sgFromSig.toString('hex'));

            sgFromPubkeys = DlcOracle.computeSignaturePubKey(publicKey, rPoint, message);
            console.log("Compute sG from pub keys and message:", sgFromPubkeys.toString('hex'));

            doSignLoop();
        }
    });
}

main();
    