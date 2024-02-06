use openssl::symm::{Cipher, Crypter, Mode, encrypt};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, AddrParseError};

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
pub enum CipherError{
    InvalidKeyLength(usize),
    CipherCreationFailed,
    PaddingEncryptionFailed,
    BlockEncryptionFailed,
    EncryptionFailed,
    
}
impl std::fmt::Display for CipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CipherError::InvalidKeyLength(len) => write!(f, "Invalid key length (must be 32 bytes)\n Found {} bytes", len),
            CipherError::CipherCreationFailed => write!(f, "Cipher creation failed"),
            CipherError::PaddingEncryptionFailed => write!(f, "Padding encryption failed"),
            CipherError::EncryptionFailed => write!(f, "Encryption failed"),
            CipherError::BlockEncryptionFailed => write!(f, "Block encryption failed"),
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
            return Err(CryptoPAnError::CipherError(CipherError::InvalidKeyLength(key.len())));
        }

        // Prepare the AES cipher for encryption.
        let mut cipher = Crypter::new(
            Cipher::aes_128_ecb(),
            Mode::Encrypt,
            &key[..16], // First 16 bytes are the AES key.
            None, // ECB mode does not use an IV.
        ).map_err(|_| CipherError::CipherCreationFailed)?;

        // Correctly size the buffer for the output of the encryption operation.
        // The AES block size is 16 bytes, so the output will also be 16 bytes.
        let mut padding = vec![0; 32]; // Output buffer sized to 16 bytes.

        // Encrypt the second half of the key to use as padding.
        // Note: `update` followed by `finalize` ensures complete encryption.
        // println!("{:?}", &key[16..].to_vec());
        encrypt(Cipher::aes_128_ecb(), &key[16..], None, &mut padding).map_err(|_| CipherError::PaddingEncryptionFailed)?;
        // cipher.update(&key[16..], &mut padding).map_err(|_| CipherError::PaddingEncryptionFailed)?;
        // cipher.finalize(&mut padding).map_err(|_| CipherError::EncryptionFailed)?;
        // println!("{:?}", padding);
        
        let padding_int = Self::to_int(&padding);

        Ok(Self {
            cipher,
            padding_int,
            masks: Self::gen_masks(),
            key: key.to_vec(),
        })
    }

    fn  _to_int(bytes: &[u8]) -> u128 {
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
        byte_array.iter().fold(0u128, |acc, &byte| (acc << 8) | u128::from(byte))
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


    fn anonymize(&mut self, addr: &str) -> Result<String, CryptoPAnError> {
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
            let f = encrypt(Cipher::aes_128_ecb(), &self.key[..16], None, &self.to_array(padded_addr, 16)).map_err(|_| CipherError::EncryptionFailed)?;
            // let f = self.encrypt_block(&self.to_array(padded_addr, 16))?;
            flip_array.push(f[0] >> 7);
        }
        let result = flip_array.into_iter().fold(0u128, |acc, x| (acc << 1) | (x as u128));

        Ok(addr ^ result)
    }

    fn __anonymize_bin(&mut self, addr: u128, version: u8) -> Result<u128, CryptoPAnError> {
        // Anonymize an IP address represented as an integer value.

        assert!(version == 4 || version == 6);
        let pos_max = if version == 4 { 32 } else { 128 };
        let ext_addr = if version == 4 { addr << 96 } else { addr };

        let mut flip_array: Vec<u8> = Vec::with_capacity(pos_max);

        for pos in 0..pos_max {


            let shift_amount = if pos >= 128 { 0 } else { 128 - pos };
            let _prefix = if shift_amount < 128 {
                ext_addr >> shift_amount
            } else {
                0
            };

            // Perform the left shift only when shift_amount is less than 128.
            let _prefix = if shift_amount < 128 {
                _prefix << shift_amount
            } else {
                _prefix
            };
            let prefix = ext_addr >> (128 - pos) << (128 - pos);

            let padded_addr: u128 = prefix | (self.padding_int & self.masks[pos]);

            let padded_addr_bytes = self.to_array(padded_addr, 16);
            let f = self.encrypt_block(&padded_addr_bytes)?;
            flip_array.push(f[0] >> 7);
        }

        let result = flip_array.into_iter().fold(0u128, |acc, x| (acc << 1) | u128::from(x));

        Ok(addr ^ result)
    }


    // This function mirrors the Python `anonymize_bin` logic.
    fn _anonymize_bin(&mut self, addr: u128, version: u8) -> Result<u128, CryptoPAnError> {
        let pos_max = if version == 4 { 32 } else { 128 };
        let mut result = 0u128;

        for pos in 0..pos_max {
            let mask = self.masks[pos];
            let prefix = addr & mask;
            let padded_addr = prefix | (self.padding_int & !mask);

            // let encrypted = self.encrypt_block(&padded_addr.to_be_bytes())?;
            let encrypted = encrypt(Cipher::aes_128_ecb(), &self.key[..16], None, &self.to_array(padded_addr, 16)).map_err(|_| CipherError::EncryptionFailed)?;
            let bit_to_flip = (encrypted[0] >> 7) & 1;
            if bit_to_flip == 1 {
                result |= 1u128 << (pos_max - pos - 1);
            }
        }

        // Mask the result for IPv4 to only affect the last 32 bits
        if version == 4 {
            return Ok((addr & (u128::MAX << 32)) | (result & 0xFFFFFFFF));
        }

        Ok(result)
    }

    fn encrypt_block(&mut self, block: &[u8]) -> Result<Vec<u8>, CryptoPAnError> {
        // Calculate the correct output buffer size.
        // Since AES block size is 16 bytes, the output buffer must be at least
        // the size of the input rounded up to the nearest block size, plus one block size for padding.
        let block_size = Cipher::aes_128_ecb().block_size();
        let output_size = ((block.len() + block_size - 1) / block_size) * block_size + block_size;
        let mut encrypted_block = vec![0; output_size];

        // Perform the encryption operation.
        let count = self.cipher.update(block, &mut encrypted_block)
            .map_err(|_| CipherError::BlockEncryptionFailed)?;

        // Finalize the encryption, ensuring all data is processed.
        let rest = self.cipher.finalize(&mut encrypted_block[count..])
            .map_err(|_| CipherError::EncryptionFailed)?;

        encrypted_block.truncate(count + rest); // Adjust the vector size to actual data length
        Ok(encrypted_block)
    }



    fn format_ip(addr: u128, version: u8) -> String {
        match version {
            4 => Ipv4Addr::from((addr & 0xFFFFFFFF) as u32).to_string(),
            6 => Ipv6Addr::from(addr).to_string(),
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
        let mut cp = CryptoPAn::new(&[21,34, 23, 141, 51, 164, 207, 128, 19, 10, 91, 22, 73, 144, 125, 16, 216, 152, 143, 131, 121, 121, 101, 39, 98, 87, 76, 45, 42, 132, 34, 2]).unwrap();
        let anonymized = cp.anonymize(addr).unwrap();
        assert_eq!(anonymized, expected);
    }
    fn run_non_key_test(addr: &str, expected: &str) {
        let mut cp = CryptoPAn::new(&[0; 32]).unwrap();
        let anonymized = cp.anonymize(addr).unwrap();
        assert_eq!(anonymized, expected);
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


