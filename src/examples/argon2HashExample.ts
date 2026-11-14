import {HashPasswordService} from "../core/services/hashPassword.service";
import type {HashAlgorithmType} from "../core/types/hashAlgorithm.type";
import {exampleRsaKeys} from "./exampleRsaKeys";

async function main(): Promise<void> {
    const passwordHash: HashPasswordService = new HashPasswordService();
    const {privateKey, publicKey} = exampleRsaKeys();
    const plainPassword: string = "correct horse battery staple";
    const hashAlgorithm: HashAlgorithmType = "argon2";
    // argon2id: the salt argument is ignored (a random 16-byte salt is generated and stored in the hash);
    // `iterations` is the time cost (at least 2) and `keyLength` the memory cost in KiB (at least 19 456 = 19 MiB).
    // The memory cost is RAM: a very large value can exhaust the machine.
    const timeCost: number = 2;
    const memoryCostKiB: number = 19_456;

    const result = await passwordHash.hashPassword(plainPassword, "", hashAlgorithm, timeCost, memoryCostKiB, "hex", privateKey);
    if (!result) {
        throw new Error("the password could not be hashed");
    }
    // store the hash and its RSA signature: verification checks the signature before the password
    console.log(`Hashed password (${hashAlgorithm}):`, result.hashedPassword);

    const isPasswordValid: boolean = await passwordHash.verifyHashPassword(
        result.hashedPassword, result.signedHash, null, plainPassword, hashAlgorithm, 0, 0, "hex", publicKey
    );
    console.log("Is it a valid password?", isPasswordValid);
}

main().catch(console.error);
