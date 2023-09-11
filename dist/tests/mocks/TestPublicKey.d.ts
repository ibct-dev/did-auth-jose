import PublicKey from '../../lib/security/PublicKey';
/**
 * A public key object used for testing
 */
export declare class TestPublicKey extends PublicKey {
    /** Its unique identifier */
    uid: number;
    defaultEncryptionAlgorithm: string;
    constructor(kid?: string);
}
