import path from "path";
import fs from "fs";

/**
 * Returning the public key RSA generated to encrypt or decrypt data
 *
 * @constructor
 */
export default function PublicKey(): string {
    const pathToPublicKey: string = path.join(process.cwd(), "src/core/constants/keypair/id_rsa_pub.pem");
    return fs.readFileSync(pathToPublicKey, 'utf8');
}
