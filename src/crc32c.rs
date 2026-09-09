//! CRC-32C (Castagnoli), as used by the Cloud KMS request/response checksums.
//!
//! Hand-rolled to avoid a dependency, and specifically *not* `crc32fast`,
//! which implements CRC-32/ISO-HDLC — a different polynomial that would
//! silently disagree with what KMS sends and make every decrypt look corrupt.
//!
//! Checksums here are an integrity check against transport corruption, not a
//! security control; ciphertext integrity comes from AES-GCM inside KMS.

/// Reflected form of the Castagnoli polynomial 0x1EDC6F41.
const POLY_REFLECTED: u32 = 0x82F6_3B78;

pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let lsb_set = crc & 1 != 0;
            crc >>= 1;
            if lsb_set {
                crc ^= POLY_REFLECTED;
            }
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::crc32c;

    #[test]
    fn standard_check_vectors() {
        // The canonical CRC-32C check value.
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(b""), 0x0000_0000);
        assert_eq!(crc32c(b"a"), 0xC1D0_4330);
        // 32 zero bytes: the shape of an actual seed plaintext.
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
    }

    #[test]
    fn detects_single_bit_flips() {
        let base = [0xABu8; 32];
        let good = crc32c(&base);
        for bit in 0..(base.len() * 8) {
            let mut flipped = base;
            flipped[bit / 8] ^= 1 << (bit % 8);
            assert_ne!(crc32c(&flipped), good, "bit {bit} went undetected");
        }
    }
}
