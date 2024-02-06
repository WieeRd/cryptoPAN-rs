use openssl::symm::{ Cipher, Crypter, Mode};
use std::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
pub enum CryptoPAnError {
    CipherError(CipherError),
    AddressParseError(AddrParseError),
}
impl std::fmt::Display for CryptoPAnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoPAnError::CipherError(err) => write!(f, "{}", err),
            CryptoPAnError::AddressParseError(err) => write!(f, "{}", err),
        }
    }
}

impl From<CipherError> for CryptoPAnError {
    fn from(err: CipherError) -> Self {
        CryptoPAnError::CipherError(err)
    }
}

impl From<AddrParseError> for CryptoPAnError {
    fn from(err: AddrParseError) -> Self {
        CryptoPAnError::AddressParseError(err)
    }
}

#[derive(Debug)]
pub enum CipherError {
    InvalidKeyLength(usize),
    CipherCreationFailed,
    EncryptionUpdateFailed,
    EncryptionFinalizeFailed,
}
impl std::fmt::Display for CipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CipherError::InvalidKeyLength(len) => write!(
                f,
                "Invalid key length (must be 32 bytes)\n Found {} bytes",
                len
            ),
            CipherError::CipherCreationFailed => write!(f, "Cipher creation failed"),
            CipherError::EncryptionUpdateFailed => write!(f, "Encryption Update failed"),
            CipherError::EncryptionFinalizeFailed => write!(f, "Encryption Finalize failed"),
        }
    }
}

pub struct CryptoPAn {
    cipher: Crypter,
    padding_int: u128,
    masks: Vec<u128>,
    key: Vec<u8>,
}

impl CryptoPAn {
    fn new(key: &[u8]) -> Result<Self, CryptoPAnError> {
        if key.len() != 32 {
            return Err(CryptoPAnError::CipherError(CipherError::InvalidKeyLength(
                key.len(),
            )));
        }

        // Prepare the AES cipher for encryption.
        let mut cipher = Crypter::new(
            Cipher::aes_128_ecb(),
            Mode::Encrypt,
            &key[..16], // First 16 bytes are the AES key.
            None,       // ECB mode does not use an IV.
        )
        .map_err(|_| CipherError::CipherCreationFailed)?;

        // Correctly size the buffer for the output of the encryption operation.
        // The AES block size is 16 bytes, so the output will also be 16 bytes.
        let block_size = Cipher::aes_128_ecb().block_size();
        let mut padding = vec![0; 16 + block_size]; // Output buffer sized to 16 bytes.

        // Encrypt the second half of the key to use as padding.
        // Note: `update` followed by `finalize` ensures complete encryption.
        let mut cnt = cipher
            .update(&key[16..], &mut padding)
            .map_err(|_| CipherError::EncryptionUpdateFailed)?;
        cnt += cipher
            .finalize(&mut padding[cnt..])
            .map_err(|_| CipherError::EncryptionFinalizeFailed)?;
        padding.truncate(cnt);

        let padding_int = Self::to_int(&padding);

        Ok(Self {
            cipher,
            padding_int,
            masks: Self::gen_masks(),
            key: key.to_vec(),
        })
    }

    fn _to_int(bytes: &[u8]) -> u128 {
        // Ensure that the byte slice has a length of up to 16 bytes
        // and pad it with zeros if it's shorter.
        let mut padded_bytes = [0u8; 16];
        let bytes_to_copy = bytes.len().min(16);
        padded_bytes[16 - bytes_to_copy..].copy_from_slice(&bytes[..bytes_to_copy]);

        // Convert the byte array to a u128 integer
        u128::from_be_bytes(padded_bytes)
    }

    fn to_int(byte_array: &[u8]) -> u128 {
        // Convert a byte array to a u64 value.
        byte_array
            .iter()
            .fold(0u128, |acc, &byte| (acc << 8) | u128::from(byte))
    }

    fn to_array(&self, int_value: u128, int_value_len: usize) -> Vec<u8> {
        // Convert a u64 value to a byte array.
        let mut byte_array: Vec<u8> = Vec::with_capacity(int_value_len);
        for i in 0..int_value_len {
            byte_array.insert(0, ((int_value >> (i * 8)) & 0xff) as u8);
        }
        byte_array
    }

    fn gen_masks() -> Vec<u128> {
        // Generates an array of bit masks to calculate n-bits padding data.
        let mask128: u128 = (0..128).fold(0u128, |acc, _| (acc << 1) | 1);
        let mut masks = vec![0u128; 128];

        for l in 0..128 {
            // self._masks[0]   <- 128 bits all 1
            // self._masks[127] <- 1
            masks[l] = mask128 >> l;
        }
        masks
    }

    fn anonymize(&mut self, addr: &str) -> Result<IpAddr, CryptoPAnError> {
        let ip: IpAddr = addr.parse()?;
        let (addr, version) = match ip {
            IpAddr::V4(ipv4) => (u128::from(u32::from(ipv4)), 4),
            IpAddr::V6(ipv6) => (u128::from(ipv6), 6),
        };

        let anonymized = self.anonymize_bin(addr, version)?;

        println!("Anonymized IP: {}", anonymized);
        Ok(Self::format_ip(anonymized, version))
    }

    fn anonymize_bin(&mut self, addr: u128, version: u8) -> Result<u128, CryptoPAnError> {
        assert!(version == 4 || version == 6);
        let pos_max = if version == 4 { 32 } else { 128 };
        let ext_addr = if version == 4 { addr << 96 } else { addr };

        let mut flip_array = Vec::new();
        for pos in 0..pos_max {
            let prefix = ext_addr >> (128 - pos) << (128 - pos);
            let padded_addr = prefix | (self.padding_int & self.masks[pos as usize]);
            let padded_bytes = self.to_array(padded_addr, 16);

            let block_size = Cipher::aes_128_ecb().block_size();
            let mut encrypted = vec![0u8; 16 + block_size];

            let mut cnt = self
                .cipher
                .update(&padded_bytes, &mut encrypted)
                .map_err(|_| CipherError::EncryptionUpdateFailed)?;
            cnt += self
                .cipher
                .finalize(&mut encrypted[cnt..])
                .map_err(|_| CipherError::EncryptionFinalizeFailed)?;
            encrypted.truncate(cnt);

            // let f = self.encrypt_block(&self.to_array(padded_addr, 16))?;
            flip_array.push((encrypted[0] >> 7) & 1);
        }
        let result = flip_array
            .into_iter()
            .fold(0u128, |acc, x| (acc << 1) | (x as u128));

        Ok(addr ^ result)
    }

    fn format_ip(addr: u128, version: u8) -> IpAddr {
        match version {
            4 => IpAddr::V4(Ipv4Addr::from((addr & 0xFFFFFFFF) as u32)),
            6 => IpAddr::V6(Ipv6Addr::from(addr)),
            _ => unreachable!(),
        }
    }
}

// test module
#[cfg(test)]
mod tests {
    use super::*;
    fn run_key_test(addr: &str, expected: &str) {
        // following key is the key used in the original crypto-pan source distribution code.
        let mut cp = CryptoPAn::new(&[
            21, 34, 23, 141, 51, 164, 207, 128, 19, 10, 91, 22, 73, 144, 125, 16, 216, 152, 143,
            131, 121, 121, 101, 39, 98, 87, 76, 45, 42, 132, 34, 2,
        ])
        .unwrap();
        let anonymized = cp.anonymize(addr).unwrap();
        assert_eq!(anonymized.to_string(), expected);
    }
    fn run_non_key_test(addr: &str, expected: &str) {
        let mut cp = CryptoPAn::new(&[0; 32]).unwrap();
        let anonymized = cp.anonymize(addr).unwrap();
        assert_eq!(anonymized.to_string(), expected);
    }

    #[test]
    fn test_anonymize_ipv4() {
        run_non_key_test("192.0.2.1", "2.90.93.17");
    }
    #[test]
    fn test_anonymize_ipv4_2() {
        run_non_key_test("192.0.2.2", "2.90.93.18");
    }
    #[test]
    fn test_anonymize_ipv4_3() {
        run_non_key_test("192.0.2.3", "2.90.93.19");
    }
    #[test]
    fn test_anonymize_ipv4_4() {
        run_non_key_test("192.0.3.3", "2.90.94.19");
    }
    #[test]
    fn test_anonymize_ipv4_5() {
        run_key_test("195.205.63.10", "255.186.223.5");
    }

    #[test]
    fn test_anonymize_ipv6() {
        run_non_key_test("2001:db8::1", "dd92:2c44:3fc0:ff1e:7ff9:c7f0:8180:7e00");
    }
    #[test]
    fn test_anonymize_ipv6_parcial() {
        run_key_test("::1", "78ff:f001:9fc0:20df:8380:b1f1:704:ed");
    }

    #[test]
    fn test_anonymize_ipv6_parcial2() {
        run_key_test("::2", "78ff:f001:9fc0:20df:8380:b1f1:704:ef");
    }

    #[test]
    fn test_anonymize_ipv6_parcial3() {
        run_key_test("::ffff", "78ff:f001:9fc0:20df:8380:b1f1:704:f838");
    }
}
