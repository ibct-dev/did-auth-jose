import EcPublicKey from './EcPublicKey';
import CryptoSuite, { SymmetricEncrypter } from '../../interfaces/CryptoSuite';
import PrivateKey from '../../security/PrivateKey';
import PublicKey from '../../security/PublicKey';
import { IDidDocumentPublicKey } from '@decentralized-identity/did-common-typescript';
/**
 * Encrypter plugin for Elliptic Curve P-256K1
 */
export declare class Secp256k1CryptoSuite implements CryptoSuite {
    getSymmetricEncrypters(): {
        [algorithm: string]: SymmetricEncrypter;
    };
    /** Encryption with Secp256k1 keys not supported */
    getEncrypters(): {};
    /** Signing algorithms */
    getSigners(): {
        ES256K: {
            sign: typeof Secp256k1CryptoSuite.sign;
            verify: typeof Secp256k1CryptoSuite.verify;
        };
    };
    /**
     * Defines constructors for the identifiers proposed in Linked Data Cryptographic Suite Registry
     * https://w3c-ccg.github.io/ld-cryptosuite-registry/#eddsasasignaturesecp256k1 plus the additional
     * ones spotted in the wild.
     */
    getKeyConstructors(): {
        Secp256k1VerificationKey2018: (keyData: IDidDocumentPublicKey) => EcPublicKey;
        EdDsaSAPublicKeySecp256k1: (keyData: IDidDocumentPublicKey) => EcPublicKey;
        EdDsaSASignatureSecp256k1: (keyData: IDidDocumentPublicKey) => EcPublicKey;
        EcdsaPublicKeySecp256k1: (keyData: IDidDocumentPublicKey) => EcPublicKey;
    };
    /**
     * Verifies the given signed content using SHA256 algorithm.
     *
     * @returns true if passed signature verification, false otherwise.
     */
    static verify(signedContent: string, signature: string, jwk: PublicKey): Promise<boolean>;
    /**
     * Sign the given content using the given private key in JWK format using algorithm SHA256.
     *
     * @param jwsHeaderParameters Header parameters in addition to 'alg' and 'kid' to be included in the JWS.
     * @returns Signed payload in compact JWS format.
     */
    static sign(content: string, jwk: PrivateKey): Promise<string>;
}
