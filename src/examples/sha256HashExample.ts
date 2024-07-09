import {HashPasswordService} from "../services/hashPassword.service";
import {HashAlgorithmType} from "../core/types/hashAlgorithm.type";

async function main(): Promise<void> {
    const passwordHash: HashPasswordService = new HashPasswordService();
    const plainPassword: string = "guyzoum1";
    const salt: string = passwordHash.generateSalt(16, "hex");
    const hashAlgorithm: HashAlgorithmType = 'sha256';

    // you must to chosen keyLength value between 1024 and 4,294,967,295.
    // But if you choose a greater number like 4,294,967,295, make sure that your PC is very strong else your pc
    // will crash because greater number needs a lot of computing power, so be careful with keyLength value.

    let hashedPassword;
    hashedPassword = await passwordHash.hashPassword(
        plainPassword, salt, hashAlgorithm, 100, 4294, "hex"
    );

    console.log(`Hashed password (${hashAlgorithm}):`, hashedPassword);
    console.log('plainPassword:', plainPassword);
    console.log('Salt:', salt);

    const isPasswordValid: boolean = await passwordHash.verifyHashPassword(
        hashedPassword, salt, plainPassword, hashAlgorithm, 100, 4294, "hex"
    );
    console.log('Is it a valid password ? ', isPasswordValid);
}

main().catch(console.error);