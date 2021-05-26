let crypto = require ("crypto");
let CryptoJS = require("crypto-js");
let fs = require('fs');
const { performance } = require("perf_hooks");

try {
    var textFile = fs.readFileSync('my-file.txt', 'utf8');
    //console.log(textFile);    
} catch(e) {
    console.log('Error:', e.stack);
}

let plainText = textFile;//'Security is freedom from, or resilience against, potential harm (or other unwanted coercive change) caused by others. Beneficiaries (technically referents) of security may be of persons and social groups, objects and institutions, ecosystems or any other entity or phenomenon vulnerable to unwanted change.';
console.log("-----------------------------------------------------------------------------------------------------------------------------------------");
console.log("The Plain Text");
console.log(plainText);
//AES key generation.
let aesKey = crypto.randomBytes(24).toString();

//RSA key generation.
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
});

let dataPacket = [];
let dPacket;
let Digital_Signature = [];
let digitalSignature;
let cipherText;
let cipheredKey;
let dHash = [];


async function encryption (plainText){
    //AES128
     cipherText = CryptoJS.AES.encrypt(plainText, aesKey).toString();

    //Hash algorithm SHA-256
    let hash = crypto.createHash('sha256').update(plainText).digest('hex');

    //Encrypting AES secret key with RSA public key.
     cipheredKey = crypto.publicEncrypt(
        {
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
        },
        // We convert the data string to a buffer using `Buffer.from`
        Buffer.from(aesKey)
    )

    //Encrypting the hash value with the RSA private key to get digital signature.
      digitalSignature = crypto.privateEncrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_PADDING
        },
        // We convert the data string to a buffer using `Buffer.from`
        Buffer.from(hash)
    )
    Digital_Signature.push(digitalSignature);
    dPacket = { "Cipher_Text": cipherText, "Ciphered_Key": cipheredKey.toString(), "Digital_Signature": digitalSignature.toString() };
    dataPacket.push(cipherText);
    dataPacket.push(cipheredKey);
    dataPacket.push(digitalSignature);
    return (dataPacket);

}

//let data_Packet =
let t0 = performance.now();
encryption(plainText);
let t1 = performance.now();

async function decryption (dataPacket){
    //Verify the Digital Signature, if the Digital Signature at the sender's side is the same as that at the reciever's side return the hash value.
    if (dataPacket[2] == Digital_Signature[0]){
        //Decrypting the digital signature by using the publicKey to get back the hash value.
        const decryptedHash = crypto.publicDecrypt(
            {
                key: publicKey,
                // In order to decrypt the data, we need to specify the
                // same hashing function and padding scheme that we used to
                // encrypt the data in the previous step
                padding: crypto.constants.RSA_PKCS1_PADDING,
                //oaepHash: "sha256",
            },
            digitalSignature
        )
        dHash.push(decryptedHash);
    }
    //Decrypting the cipherKey to AES key by using the privateKey of the RSA.
    const decryptedKey = crypto.privateDecrypt(
        {
                key: privateKey,
                // In order to decrypt the data, we need to specify the
                // same hashing function and padding scheme that we used to
                // encrypt the data in the previous step
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                //oaepHash: "sha256",
        },
        cipheredKey
    )
    
    let decryptedPlainText = CryptoJS.AES.decrypt(dataPacket[0], decryptedKey.toString());
    let originalText = decryptedPlainText.toString(CryptoJS.enc.Utf8);

    return(originalText);
}
console.log("-----------------------------------------------------------------------------------------------------------------------------------------");
console.log("The Data Packet", dPacket);
console.log("Encrytion took " + (t1 - t0) + " milliseconds.")
let t3 = performance.now();
let decryptedText = decryption(dataPacket);
let t4 = performance.now();
console.log("-----------------------------------------------------------------------------------------------------------------------------------------");
console.log('decryption',decryptedText);
console.log("Decryption took " + (t4-t3) + " milliseconds.");
console.log("total time taken by the process is " + ((t1-t0) + (t4-t3)) + " milliseconds.");
console.log("-----------------------------------------------------------------------------------------------------------------------------------------");


