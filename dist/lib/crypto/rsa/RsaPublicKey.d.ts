import PublicKey, { RecommendedKeyType } from '../../security/PublicKey';
import { IDidDocumentPublicKey } from '@decentralized-identity/did-common-typescript';
/**
 * Represents an Rsa public key
 * @class
 * @extends PublicKey
 */
export default class RsaPublicKey extends PublicKey {
    kty: RecommendedKeyType;
    readonly defaultEncryptionAlgorithm: string;
    /** Modulus */
    n: string;
    /** Exponent */
    e: string;
    /**
     * A Rsa JWK
     * @param n The Rsa modulus in Base64urlUInt encoding as specified by RFC7518 6.3.1.1
     * @param e The Rsa public exponent in Base64urlUInt encoding as specified by RFC7518 6.3.1.2
     */
    constructor(keyData: IDidDocumentPublicKey);
}
