/// <reference types="node" />
import RsaPublicKey from './RsaPublicKey';
import CryptoSuite, { SymmetricEncrypter } from '../../interfaces/CryptoSuite';
import { IDidDocumentPublicKey } from '@decentralized-identity/did-common-typescript';
import PrivateKey from '../../security/PrivateKey';
import PublicKey from '../../security/PublicKey';
/**
 * Encrypter plugin for RsaSignature2018
 */
export declare class RsaCryptoSuite implements CryptoSuite {
    getSymmetricEncrypters(): {
        [algorithm: string]: SymmetricEncrypter;
    };
    /** Encryption algorithms */
    getEncrypters(): {
        'RSA-OAEP': {
            encrypt: typeof RsaCryptoSuite.encryptRsaOaep;
            decrypt: typeof RsaCryptoSuite.decryptRsaOaep;
        };
    };
    /** Signing algorithms */
    getSigners(): {
        RS256: {
            sign: typeof RsaCryptoSuite.signRs256;
            verify: typeof RsaCryptoSuite.verifySignatureRs256;
        };
        RS512: {
            sign: typeof RsaCryptoSuite.signRs512;
            verify: typeof RsaCryptoSuite.verifySignatureRs512;
        };
    };
    getKeyConstructors(): {
        RsaVerificationKey2018: (keyData: IDidDocumentPublicKey) => RsaPublicKey;
    };
    /**
     * Verifies the given signed content using RS256 algorithm.
     *
     * @returns true if passed signature verification, false otherwise.
     */
    static verifySignatureRs256(signedContent: string, signature: string, jwk: PublicKey): Promise<boolean>;
    /**
     * Sign the given content using the given private key in JWK format using algorithm RS256.
     * TODO: rewrite to get rid of node-jose dependency.
     *
     * @param jwsHeaderParameters Header parameters in addition to 'alg' and 'kid' to be included in the JWS.
     * @returns Signed payload in compact JWS format.
     */
    static signRs256(content: string, jwk: PrivateKey): Promise<string>;
    /**
     * Verifies the given signed content using RS512 algorithm.
     *
     * @returns true if passed signature verification, false otherwise.
     */
    static verifySignatureRs512(signedContent: string, signature: string, jwk: PublicKey): Promise<boolean>;
    /**
     * Sign the given content using the given private key in JWK format using algorithm RS512.
     * TODO: rewrite to get rid of node-jose dependency.
     *
     * @param jwsHeaderParameters Header parameters in addition to 'alg' and 'kid' to be included in the JWS.
     * @returns Signed payload in compact JWS format.
     */
    static signRs512(content: string, jwk: PrivateKey): Promise<string>;
    /**
     * Rsa-OAEP encrypts the given data using the given public key in JWK format.
     */
    static encryptRsaOaep(data: Buffer, jwk: PublicKey): Promise<Buffer>;
    /**
     * Rsa-OAEP decrypts the given data using the given private key in JWK format.
     * TODO: correctly implement this after getting rid of node-jose dependency.
     */
    static decryptRsaOaep(data: Buffer, jwk: PrivateKey): Promise<Buffer>;
}
