"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const TestPublicKey_1 = require("./TestPublicKey");
/**
 * A private key object used for testing
 */
class TestPrivateKey extends TestPublicKey_1.TestPublicKey {
    constructor() {
        super(...arguments);
        this.defaultSignAlgorithm = 'test';
    }
    getPublicKey() {
        return this;
    }
}
exports.default = TestPrivateKey;
//# sourceMappingURL=TestPrivateKey.js.map