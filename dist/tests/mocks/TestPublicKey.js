"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TestPublicKey = void 0;
const PublicKey_1 = __importDefault(require("../../lib/security/PublicKey"));
/**
 * A public key object used for testing
 */
class TestPublicKey extends PublicKey_1.default {
    constructor(kid) {
        super();
        this.defaultEncryptionAlgorithm = 'test';
        this.kty = 'test';
        this.uid = Math.round(Math.random() * Number.MAX_SAFE_INTEGER);
        this.kid = kid !== undefined ? kid : this.uid.toString();
    }
}
exports.TestPublicKey = TestPublicKey;
//# sourceMappingURL=TestPublicKey.js.map