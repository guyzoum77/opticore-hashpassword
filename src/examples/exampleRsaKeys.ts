import {generateKeyPairSync} from "node:crypto";

/**
 * RSA key pair used by the examples to sign (hashPassword) and check (verifyHashPassword) the hashes.
 * Generated at run time so that no private key is ever committed; in an application, load your own keys
 * from a secret store or protected files instead.
 */
export function exampleRsaKeys(): { privateKey: string; publicKey: string } {
    return generateKeyPairSync("rsa", {
        modulusLength: 3072,
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
}
