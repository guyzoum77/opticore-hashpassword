import colors from "ansi-colors";
import * as bcrypt from "bcrypt";
import * as argon2 from "argon2";
import {scrypt} from "scrypt-js";
import crypto from "crypto";
import {HashContratAbstract} from "../abstract/hashContrat.abstract";
import {HashAlgorithmType} from "../types/hashAlgorithm.type";
import {dateTimeFormattedUtils} from "../utils/dateTimeFormatted.utils";

export class HashPasswordService extends HashContratAbstract {

    /**
     *
     * @param encryptedPassword
     * @param privateKey
     * @param bufferEncoding
     *
     * The method decryptPasswordRSA is decrypting the encrypted password using the private RSA key
     *
     * Return decrypted data or handled error if any parameters are not provided or are wrong
     */
    decryptPasswordRSA(encryptedPassword: string, privateKey: string, bufferEncoding: BufferEncoding): string {
        let decrypted;
        try {
            const buffer: Buffer = Buffer.from(encryptedPassword, bufferEncoding);
            decrypted = crypto.privateDecrypt(privateKey, buffer);
        } catch (err: any) {
            console.log(`${colors.red(`✘`)} ${colors.bgRed(`[ ${colors.bold(`${colors.white("Crypto privateDecrypt error")}`)} ]`)} | ${dateTimeFormattedUtils()} | [ ${colors.red(`${colors.bold("Error occurring at privateDecrypt level")}`)} ] | [ ${colors.bold(`${err.name}`)} ] ${colors.red(`${err.stack}`)} - ${colors.red(`${err.message}`)} - [ ${colors.red(`${colors.bold(`HttpCode`)}`)} ] ${colors.red(`${colors.bold(`406`)}`)} `);
            return "";
        }

        return decrypted.toString(bufferEncoding);
    }

    /**
     *
     * @param password
     * @param publicKey
     * @param bufferEncoding
     *
     * The method encryptPasswordRSA is encrypting the hashed password using the public RSA key.
     *
     * Return encrypted data or handled error if any parameters are not provided or are wrong
     */
    encryptPasswordRSA(password: string, publicKey: string, bufferEncoding: BufferEncoding): string {
        try {
            const buffer: Buffer = Buffer.from(password);
            const encrypted: Buffer = crypto.publicEncrypt(publicKey, buffer);

            return encrypted.toString(bufferEncoding);
        } catch (err: any) {
            console.log(`${colors.red(`✘`)} ${colors.bgRed(`[ ${colors.bold(`${colors.white("Crypto publicEncrypt error")}`)} ]`)} | ${dateTimeFormattedUtils()} | [ ${colors.red(`${colors.bold("Error occurring at publicEncrypt level")}`)} ] | [ ${colors.bold(`${err.name}`)} ] ${colors.red(`${err.stack}`)} - ${colors.red(`${err.message}`)} - [ ${colors.red(`${colors.bold(`HttpCode`)}`)} ] ${colors.red(`${colors.bold(`406`)}`)} `);
            return "";
        }
    }

    /**
     *
     * @param length
     * @param bufferEncoding
     *
     * The method generateSalt is generating a random salt for hashing.
     *
     * Return a strong pseudorandom data or handling an error and return the callback function
     */
    generateSalt(length: number, bufferEncoding: BufferEncoding): string {
        try {
            return crypto.randomBytes(length).toString(bufferEncoding);
        } catch (err: any) {
            console.log(`${colors.red(`✘`)} ${colors.bgRed(`[ ${colors.bold(`${colors.white("Crypto randomBytes error")}`)} ]`)} | ${dateTimeFormattedUtils()} | [ ${colors.red(`${colors.bold("Error occurring at randomBytes level")}`)} ] | [ ${colors.bold(`${err.name}`)} ] ${colors.red(`${err.stack}`)} - ${colors.red(`${err.message}`)} - [ ${colors.red(`${colors.bold(`HttpCode`)}`)} ] ${colors.red(`${colors.bold(`406`)}`)} `);
            return "";
        }
    }

    /**
     *
     * @param password
     * @param salt
     * @param algorithm
     * @param iterations
     * @param keyLength
     * @param bufferEncoding
     *
     * When it comes to secure hash algorithms, especially for cryptographic purposes like password hashing, some are more secure and commonly recommended due to their resistance to attacks. Here is a list of some of the most secure hash algorithms:
     *
     * SHA-512 (Secure Hash Algorithm 512-bit): Part of the SHA-2 family, it produces a 512-bit hash value and is considered very secure.
     *
     * SHA-256 (Secure Hash Algorithm 256-bit): Also part of the SHA-2 family, it produces a 256-bit hash value and is widely used and secure.
     *
     * SHA-3 (Secure Hash Algorithm 3): The latest member of the Secure Hash Algorithm family, it offers different hash lengths like SHA-3-256, SHA-3-512, etc. It is designed to be more secure than SHA-2.
     *
     * BLAKE2: Faster than MD5, SHA-1, and SHA-2 while maintaining a similar level of security. It comes in variants like BLAKE2b (optimized for 64-bit platforms) and BLAKE2s (optimized for 8- to 32-bit platforms).
     *
     * Argon2: The winner of the Password Hashing Competition (PHC) in 2015. It is highly secure and designed specifically for hashing passwords.
     *
     * bcrypt: Based on the Blowfish cipher, bcrypt is a password-hashing function that includes a salt to protect against rainbow table attacks and can handle brute-force attacks through its computational cost parameter.
     *
     * scrypt: Designed to be both computationally intensive and memory-hard, which makes it more resistant to hardware-based brute-force attacks.
     *
     * The hashPassword method hashes the password according
     * to HashAlgorithmType digest algorithm (sha256, sha512, or sha1 ...)
     * with a specified number of iterations, key length, and a bufferEncoding
     *
     * Return data hashed or handled an any error
     */
    async hashPassword(password: string, salt: string, algorithm: HashAlgorithmType, iterations: number,
                       keyLength: number, bufferEncoding: BufferEncoding | undefined): Promise<any> {
        switch (algorithm) {
            case 'sha256':
            case 'sha512':
            case 'sha3-256':
            case 'sha3-512':
            case 'blake2b512':
                try {
                    return new Promise((resolve, reject): void => {
                        crypto.pbkdf2(
                            password,
                            salt,
                            iterations,
                            keyLength,
                            algorithm,
                            (err: Error | null, derivedKey: Buffer): void => {
                                if (err) {
                                    console.log(`${colors.red(`✘`)} ${colors.bgRed(`[ ${colors.bold(`${colors.white("crypto pbkdf2 error")}`)} ]`)} | ${dateTimeFormattedUtils()} | [ ${colors.red(`${colors.bold("Error occurring at pbkdf2 level")}`)} ] | [ ${colors.bold(`${err.name}`)} ] ${colors.red(`${err.stack}`)} - ${colors.red(`${err.message}`)} - [ ${colors.red(`${colors.bold(`HttpCode`)}`)} ] ${colors.red(`${colors.bold(`406`)}`)} `);
                                    reject(err);
                                }
                                resolve(derivedKey.toString(bufferEncoding));
                            });
                    });
                } catch (error: any) {
                    return console.log(`${colors.red(`✘`)} ${colors.bgRed(`${colors.bold(`${colors.white("Hash algorithm error")}`)}`)} | ${dateTimeFormattedUtils()} | [ ${colors.red(`${colors.bold("Unsupported")}`)} ] | [ ${colors.bold("Unsupported hash")} ] ${colors.red("")} - [ ${colors.red(`${colors.bold(`HttpCode`)}`)} ] ${colors.red(`${colors.bold("406")}`)} `);
                }
            case 'bcrypt':
                try {
                    return bcrypt.hash(password, await bcrypt.genSalt());
                } catch (err: any) {
                    return console.log(`${colors.red(`✘`)} ${colors.bgRed(`${colors.bold(`${colors.black("bcrypt Hashing error ")}`)}`)} | ${dateTimeFormattedUtils()} | [ ${colors.red(`${colors.bold("Error occurring at bcrypt level")}`)} ] - [ ${colors.red(`${err.code}`)} ] - ${colors.red(`${err.message}`)} - [ ${colors.red(`${colors.bold(`HttpCode`)}`)} ] ${colors.red(`${colors.bold("406")}`)} `);
                }
            case 'scrypt':
                try {
                    const passwordBuffer: Buffer = Buffer.from(password);
                    const saltBuffer: Buffer = Buffer.from(salt);
                    const derivedKey: Uint8Array = await scrypt(passwordBuffer, saltBuffer, iterations, 8, 1, keyLength);

                    return Buffer.from(derivedKey).toString(bufferEncoding);
                } catch (err: any) {
                    return console.log(`${colors.red(`✘`)} ${colors.bgRed(`${colors.bold(`${colors.black("Scrypt Hashing error ")}`)}`)} | ${dateTimeFormattedUtils()} | [ ${colors.red(`${colors.bold("Error occurring at scrypt level")}`)} ] - [ ${colors.red(`${err.code}`)} ] - ${colors.red(`${err.message}`)} - [ ${colors.red(`${colors.bold(`HttpCode`)}`)} ] ${colors.red(`${colors.bold("406")}`)} `);
                }
            case 'argon2':
                try {
                    return await argon2.hash(
                        password,
                        {
                            salt: Buffer.from(salt),
                            timeCost: iterations,
                            memoryCost: keyLength,
                            type: argon2.argon2id
                        }
                    );
                } catch (e: any) {
                    switch (e.code) {
                        case "ERR_ASSERTION":
                            return console.log(`${colors.red(`✘`)} ${colors.bgRed(`${colors.bold(`${colors.black(" Hashing error ")}`)}`)} | ${dateTimeFormattedUtils()} | [ ${colors.red(`${colors.bold("Argon2 Memory cost")}`)} ] - [ ${colors.red("AssertionError")} ] ${colors.red(`${e.code}`)} - ${colors.red(`${e.message}`)} - [ ${colors.red(`${colors.bold(`HttpCode`)}`)} ] ${colors.red(`${colors.bold("406")}`)} `);
                        default:
                            return console.log(`${colors.red(`✘`)} ${colors.bgRed(`[ ${colors.bold(`${colors.white(" Argon2 hashing error ")}`)} ]`)} | ${dateTimeFormattedUtils()} | [ ${colors.red(`${colors.bold("Error occurring")}`)} ] | [ ${colors.bold("Type error")} ] ${colors.red(`${e.code}`)} - ${colors.red(`${e.message}`)} - [ ${colors.red(`${colors.bold(`HttpCode`)}`)} ] ${colors.red(`${colors.bold("406")}`)} `);
                    }
                }
            default:
                return console.log(`${colors.red(`✘`)} ${colors.bgRed(`[ ${colors.bold(`${colors.white(" Unsupported hash ")}`)} ]`)} | ${dateTimeFormattedUtils()} | [ ${colors.red(`${colors.bold("Error occurring")}`)} ] | ${colors.red("the hash you entered is not supported, we suggest choosing valid hashes like SHA-256, Argon2 or others")} - [ ${colors.red(`${colors.bold(`HttpCode`)}`)} ] ${colors.red(`${colors.bold("406")}`)} `);
        }
    }

    /**
     *
     * @param storedHashedPassword
     * @param storedSalt
     * @param providedPassword
     * @param algorithm
     * @param iterations
     * @param keyLength
     * @param bufferEncoding
     *
     * The verifyPassword method takes the stored hashed password, stored salt, provided password, hash algorithm,
     * iterations, and key length as parameters.
     * It hashes the provided password with the stored salt and compares it to the stored hashed password,
     * returning true if they match, otherwise false.
     */
    async verifyHashPassword(storedHashedPassword: string, storedSalt: string, providedPassword: string,
                             algorithm: HashAlgorithmType, iterations: number, keyLength: number,
                             bufferEncoding: BufferEncoding | undefined): Promise<boolean> {
        const hashedProvidedPassword = await this.hashPassword(
            providedPassword,
            storedSalt,
            algorithm,
            iterations,
            keyLength,
            bufferEncoding
        );
        return storedHashedPassword === hashedProvidedPassword;
    }
}