"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProtectionFormat = void 0;
/**
 * Enum to define different protection formats
 */
var ProtectionFormat;
(function (ProtectionFormat) {
    /**
     * Format for a flat JSON signature
     */
    ProtectionFormat[ProtectionFormat["FlatJsonJws"] = 0] = "FlatJsonJws";
    /**
     * Format for a compact JSON signature
     */
    ProtectionFormat[ProtectionFormat["CompactJsonJws"] = 1] = "CompactJsonJws";
    /**
     * Format for a compact JSON encryption
     */
    ProtectionFormat[ProtectionFormat["CompactJsonJwe"] = 2] = "CompactJsonJwe";
    /**
     * Format for a flat JSON encryption
     */
    ProtectionFormat[ProtectionFormat["FlatJsonJwe"] = 3] = "FlatJsonJwe";
})(ProtectionFormat = exports.ProtectionFormat || (exports.ProtectionFormat = {}));
//# sourceMappingURL=ProtectionFormat.js.map