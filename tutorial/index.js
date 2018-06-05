const randomBytes = require('crypto').randomBytes;
const fs = require('fs');
const path = require('path');
const DlcOracle = require('dlc-oracle-nodejs').DlcOracle;

let oneTimeSigningKey;
let privateKey;

function getOrCreateKey() {
	let key;
    let keyFile = path.join(__dirname,"privkey.hex");
    if(fs.existsSync(keyFile)) {
        key = fs.readFileSync(keyFile);
    } else {
        key = randomBytes(32);
        fs.writeFileSync(keyFile, privateKey);
    }
	return key;
}

function main() {
    privateKey = getOrCreateKey();

    let publicKey = DlcOracle.publicKeyFromPrivateKey(privateKey);
    console.log("Oracle Public Key: ",publicKey.toString('hex'));

    generateAndPrintKey();
}

function generateAndPrintKey() {
    oneTimeSigningKey = DlcOracle.generateOneTimeSigningKey();
    let rPoint = DlcOracle.publicKeyFromPrivateKey(oneTimeSigningKey);
    console.log("R-Point for next publication: ",rPoint.toString('hex'));
    setTimeout(() => { signValueAndPrint(); }, 60000);
}

function signValueAndPrint() {
    // Generate a random number between 10000-20000
    let value = Math.floor(Math.random() * 10000) + 10000;

    // Generate message to sign. Uses the same encoding as expected by LIT when settling the contract
    let message = DlcOracle.generateNumericMessage(value);
    
    // Sign the message
    let signature = DlcOracle.computeSignature(privateKey, oneTimeSigningKey, message);

    console.log("Value published: ", value);
    console.log("Signature: ", signature.toString('hex'));

    generateAndPrintKey();
}

main();