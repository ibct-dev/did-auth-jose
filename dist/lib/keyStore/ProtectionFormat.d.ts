/**
 * Enum to define different protection formats
 */
export declare enum ProtectionFormat {
    /**
     * Format for a flat JSON signature
     */
    FlatJsonJws = 0,
    /**
     * Format for a compact JSON signature
     */
    CompactJsonJws = 1,
    /**
     * Format for a compact JSON encryption
     */
    CompactJsonJwe = 2,
    /**
     * Format for a flat JSON encryption
     */
    FlatJsonJwe = 3
}
