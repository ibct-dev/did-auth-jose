import CryptoSuite, { Encrypter, Signer, SymmetricEncrypter } from './interfaces/CryptoSuite';
import { IDidDocumentPublicKey } from '@decentralized-identity/did-common-typescript';
import JweToken from './security/JweToken';
import JwsToken from './security/JwsToken';
/**
 * Utility class to handle all CryptoSuite dependency injection
 */
export default class CryptoFactory {
    private encrypters;
    private symmetricEncrypters;
    private signers;
    private defaultSymmetricAlgorithm;
    private keyConstructors;
    /**
     * Constructs a new CryptoRegistry
     * @param suites The suites to use for dependency injeciton
     */
    constructor(suites: CryptoSuite[], defaultSymmetricAlgorithm?: string);
    /**
     * constructs the jwe to be encrypted or decrypted
     * @param content content for the JWE
     */
    constructJwe(content: string | object): JweToken;
    /**
     * constructs the jws to be signed or verified
     * @param content content for the JWS
     */
    constructJws(content: string | object): JwsToken;
    /**
     * Given a public key definition from a DID Document, constructs a JWK public key. Throws an error
     * if the key definition cannot be converted.
     *
     * @param key publicKey object from a {@link DidDocument}
     * @returns The same key as a {@link PublicKey}
     */
    constructPublicKey(publicKey: IDidDocumentPublicKey): import(".").PublicKey;
    /**
     * Gets the Encrypter object given the encryption algorithm's name
     * @param name The name of the algorithm
     * @returns The corresponding Encrypter, if any
     */
    getEncrypter(name: string): Encrypter;
    /**
     * Gets the Signer object given the signing algorithm's name
     * @param name The name of the algorithm
     * @returns The corresponding Signer, if any
     */
    getSigner(name: string): Signer;
    /**
     * Gets the SymmetricEncrypter object given the symmetric encryption algorithm's name
     * @param name The name of the algorithm
     * @returns The corresponding SymmetricEncrypter, if any
     */
    getSymmetricEncrypter(name: string): SymmetricEncrypter;
    /**
     * Gets the default symmetric encryption algorithm to use
     */
    getDefaultSymmetricEncryptionAlgorithm(): string;
}
