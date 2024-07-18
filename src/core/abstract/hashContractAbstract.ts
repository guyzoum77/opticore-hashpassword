import {HashAlgorithmType} from "../types/hashAlgorithm.type";
import {BinaryToTextEncoding} from "node:crypto";

export abstract class HashContractAbstract {

    /**
     *
     * @param length
     * @param bufferEncoding
     */
    abstract generateSalt(length: number, bufferEncoding: BufferEncoding ): string;

    /**
     *
     * @param password
     * @param salt
     * @param algorithm
     * @param iterations
     * @param keyLength
     * @param bufferEncoding
     * @param privateRSAKey
     */
    abstract hashPassword(password: string, salt: string, algorithm: HashAlgorithmType,
                          iterations: number, keyLength: number,
                          bufferEncoding: BufferEncoding, privateRSAKey: string): Promise<any>;

    /**
     *
     * @param encryptedPassword
     * @param privateKey
     * @param bufferEncoding
     */
    abstract decryptPasswordRSA(encryptedPassword: string, privateKey: string, bufferEncoding: BufferEncoding ): string;

    /**
     *
     * @param storedHashedPassword
     * @param signedHashStored
     * @param storedSalt
     * @param providedPassword
     * @param algorithm
     * @param iterations
     * @param keyLength
     * @param bufferEncoding
     * @param publicRSAKey
     */
    abstract verifyHashPassword(storedHashedPassword: string, signedHashStored: any, storedSalt: any, providedPassword: string,
                                algorithm: HashAlgorithmType, iterations: number, keyLength: number,
                                bufferEncoding: BufferEncoding | BinaryToTextEncoding, publicRSAKey: string): Promise<boolean | void>;

    /**
     *
     * @param hashedPassword
     * @param signedHash
     * @param bufferEncoding
     * @param publicKey
     */
    protected abstract verifySignedHash(hashedPassword: any, signedHash: any, bufferEncoding: BufferEncoding | BinaryToTextEncoding, publicKey: string): boolean;
}