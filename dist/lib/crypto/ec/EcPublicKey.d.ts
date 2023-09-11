import PublicKey, { RecommendedKeyType } from '../../security/PublicKey';
import { IDidDocumentPublicKey } from '@decentralized-identity/did-common-typescript';
/**
 * Represents an Elliptic Curve public key
 * @class
 * @extends PublicKey
 */
export default class EcPublicKey extends PublicKey {
    kty: RecommendedKeyType;
    /** curve */
    crv: string;
    /** x co-ordinate */
    x: string;
    /** y co-ordinate */
    y: string;
    /**
     * An Elliptic Curve JWK
     * @param keyData The IDidDocumentPublicKey containing the elliptic curve public key parameters.
     */
    constructor(keyData: IDidDocumentPublicKey);
}
