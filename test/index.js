const DlcOracle = require('dlc-oracle-nodejs').DlcOracle;
const randomBytes = require('crypto').randomBytes;
const readline = require('readline');
const fs = require('fs');
const assert = require('assert');
const path = require('path');

function main() {
    var privateKey;
    var keyFile = path.join(__dirname,"testdata","privkey.hex");
    privateKey = Buffer.from(fs.readFileSync(keyFile).toString().trim(),'hex');
    pubKey = DlcOracle.publicKeyFromPrivateKey(privateKey);
    otsKeysHex = fs.readFileSync(path.join(__dirname,"testdata","one-time-signing-keys.hex")).toString().split('\n');
    messagesHex = fs.readFileSync(path.join(__dirname,"testdata","messages.hex")).toString().split('\n');
    sigsHex = fs.readFileSync(path.join(__dirname,"testdata","signatures.hex")).toString().split('\n');
    sGsFromSigHex = fs.readFileSync(path.join(__dirname,"testdata","signature-pubkeys-from-sig.hex")).toString().split('\n');
    sGsFromMsgHex = fs.readFileSync(path.join(__dirname,"testdata","signature-pubkeys-from-message.hex")).toString().split('\n');

    for(var i = 0; i < otsKeysHex.length; i++) {
        if(otsKeysHex[i] === '') break;
        oneTimeKey = Buffer.from(otsKeysHex[i],'hex');
        oneTimePubKey = DlcOracle.publicKeyFromPrivateKey(oneTimeKey);

        message = Buffer.from(messagesHex[i],'hex');
        expectedSig = Buffer.from(sigsHex[i],'hex');
        expectedsG1 = Buffer.from(sGsFromSigHex[i],'hex');
        expectedsG2 = Buffer.from(sGsFromMsgHex[i],'hex');
        
        assert(Buffer.compare(expectedsG1, expectedsG2) == 0, "sGs are not equal. This is an issue in the Go code that generated the testset.");

        calculatedSig = DlcOracle.computeSignature(privateKey, oneTimeKey, message);

        assert(Buffer.compare(calculatedSig, expectedSig) == 0, "Signature mismatch");

                calculatedsG1 = DlcOracle.publicKeyFromPrivateKey(calculatedSig);

        assert(Buffer.compare(calculatedsG1, expectedsG1) == 0, "sG from signature incorrect");

        calculatedsG2 = DlcOracle.computeSignaturePubKey(pubKey, oneTimePubKey, message);

        assert(Buffer.compare(calculatedsG2, expectedsG2) == 0, "sG from message");

        if(i % 100 == 0) {
            console.log("Testing signatures: ", i);
        }
    }

}

main();
    
