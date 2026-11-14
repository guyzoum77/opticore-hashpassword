import {HashPasswordService} from "../core/services/hashPassword.service";
import type {HashAlgorithmType} from "../core/types/hashAlgorithm.type";
import {exampleRsaKeys} from "./exampleRsaKeys";

async function main(): Promise<void> {
    const passwordHash: HashPasswordService = new HashPasswordService();
    const {privateKey, publicKey} = exampleRsaKeys();
    const plainPassword: string = "correct horse battery staple";
    const hashAlgorithm: HashAlgorithmType = "bcrypt";
    // bcrypt generates and embeds its own salt, so the salt, iterations and key length arguments are not used;
    // passwords longer than 72 bytes (UTF-8) are refused because bcrypt would silently truncate them.

    const result = await passwordHash.hashPassword(plainPassword, "", hashAlgorithm, 0, 0, "hex", privateKey);
    if (!result) {
        throw new Error("the password could not be hashed");
    }
    // store the hash and its RSA signature: verification checks the signature before the password
    console.log(`Hashed password (${hashAlgorithm}):`, result.hashPassword);

    const isPasswordValid: boolean = await passwordHash.verifyHashPassword(
        result.hashPassword, result.signedHash, null, plainPassword, hashAlgorithm, 0, 0, "hex", publicKey
    );
    console.log("Is it a valid password?", isPasswordValid);
}

main().catch(console.error);
