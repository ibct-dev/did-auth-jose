import EcPublicKey from './EcPublicKey';
import PrivateKey from '../../security/PrivateKey';
import PublicKey from '../../security/PublicKey';
import { IDidDocumentPublicKey } from '@decentralized-identity/did-common-typescript';
/**
 * Represents an Elliptic Curve private key
 * @class
 * @extends PrivateKey
 */
export default class EcPrivateKey extends EcPublicKey implements PrivateKey {
    /** ECDSA w/ secp256k1 Curve */
    readonly defaultSignAlgorithm: string;
    /** Private exponent */
    d: string;
    /**
     * Constructs a private key given a DID Document public key descriptor containing additional private key
     * information.
     *
     * TODO: This feels odd, should define a separate type.
     *
     * @param key public key object with additional private key information
     */
    constructor(key: IDidDocumentPublicKey);
    /**
     * Wraps a EC private key in jwk format into a Did Document public key object with additonal information
     * @param kid Key ID
     * @param jwk JWK of the private key
     */
    static wrapJwk(kid: string, jwk: any): EcPrivateKey;
    /**
     * Generates a new private key
     * @param kid Key ID
     */
    static generatePrivateKey(kid: string): Promise<EcPrivateKey>;
    getPublicKey(): PublicKey;
}
