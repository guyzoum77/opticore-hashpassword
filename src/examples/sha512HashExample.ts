import {randomBytes} from "node:crypto";
import {HashPasswordService} from "../core/services/hashPassword.service";
import type {HashAlgorithmType} from "../core/types/hashAlgorithm.type";
import {exampleRsaKeys} from "./exampleRsaKeys";

async function main(): Promise<void> {
    const passwordHash: HashPasswordService = new HashPasswordService();
    const {privateKey, publicKey} = exampleRsaKeys();
    const plainPassword: string = "correct horse battery staple";
    // a new random salt (at least 16 bytes) for each password
    const salt: string = randomBytes(16).toString("hex");
    const hashAlgorithm: HashAlgorithmType = "sha512";
    // PBKDF2 minimums for new hashes: 210 000 iterations for sha512 / sha3-512 / blake2b512 and a derived key of
    // at least 16 bytes; weaker values are refused (hashPassword then resolves to undefined)
    const iterations: number = 210_000;
    const keyLength: number = 64;

    const result = await passwordHash.hashPassword(plainPassword, salt, hashAlgorithm, iterations, keyLength, "hex", privateKey);
    if (!result) {
        throw new Error("the password could not be hashed");
    }
    // store result.signedHash ("salt$hash") with the algorithm, the iterations and the key length
    console.log(`Hashed password (${hashAlgorithm}):`, result.signedHash);

    const isPasswordValid: boolean = await passwordHash.verifyHashPassword(
        result.hashedPassword, result.signedHash, salt, plainPassword, hashAlgorithm, iterations, keyLength, "hex", publicKey
    );
    console.log("Is it a valid password?", isPasswordValid);
}

main().catch(console.error);
