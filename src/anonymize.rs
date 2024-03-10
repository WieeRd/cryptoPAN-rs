use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Defines a common interface for encrypting a 128-bit data.
///
/// Although AES-128 is commonly used by CryptoPAn implementations, any 128-bit [block cipher]
/// can be used as a encryption backend. As a result, this library is designed so that [`Anonymizer`]
/// is generic over [`Encrypter`].
///
/// It is the implementer's responsibility to ensure that the encrypter is:
///
/// - **Deterministic**: Always produces same output when given same input.
/// - **Secure**: Cryptographically secure, to prevent unauthorized decryption.
/// - **Efficient**: The encryption happens frequently during an anonymization\
///   (128 times per each IPv6 address) and needs to be reasonably fast.
///
/// [block cipher]: https://en.wikipedia.org/wiki/Block_cipher
pub trait Encrypter: Sized {
    /// Initializes an [`Encrypter`] from a 128-bit key.
    fn from_key(key: &[u8; 16]) -> Self;

    /// Encrypts a 128-bit block data.
    ///
    /// # Note
    ///
    /// Cipher implementations often require mutable access to its internal state during an
    /// encryption. In these cases, [interior mutability][std::cell] such as `UnsafeCell` will have
    /// to be used and the implementer must ensure that the output of this method is deterministic.
    fn encrypt(&self, input: &[u8; 16]) -> [u8; 16];
}

pub struct Anonymizer<E: Encrypter> {
    encrypter: E,
    padding: u128,
}

impl<E: Encrypter> Anonymizer<E> {
    pub fn new(key: &[u8; 32]) -> Self {
        let (enc_key, pad_key) = key.split_at(16);

        // array cannot be split into arrays due to const generic limitations
        // https://github.com/rust-lang/rust/issues/90091
        let enc_key: &[u8; 16] = enc_key.try_into().unwrap();
        let pad_key: &[u8; 16] = pad_key.try_into().unwrap();

        let encrypter = Encrypter::from_key(enc_key);
        Self::with_encrypter(encrypter, pad_key)
    }

    pub fn with_encrypter(encrypter: E, padding: &[u8; 16]) -> Self {
        let padding = encrypter.encrypt(padding);
        let padding = u128::from_be_bytes(padding);

        Self { encrypter, padding }
    }

    pub fn anonymize(&mut self, addr: IpAddr) -> IpAddr {
        let (addr_int, version) = match addr {
            IpAddr::V4(ipv4) => (u128::from(u32::from(ipv4)), 4),
            IpAddr::V6(ipv6) => (u128::from(ipv6), 6),
        };

        let anonymized = self.anonymize_bin(addr_int, version);

        Self::format_ip(anonymized, version)
    }

    /// Anonymizes an IP address string while preserving the subnet structure.
    ///
    /// This is a convenience method over [`anonymize()`] to accept formatted IP string
    /// instead of an [`IpAddr`]. If there is a possibility of invalid inputs, [`anonymize()`]
    /// should be prefered in order to handle parsing failure.
    ///
    /// # Panics
    ///
    /// Panics if the input string is not a correctly formatted IPv4 or IPv6 address.
    ///
    /// [`anonymize()`]: CryptoPAn::anonymize()
    #[allow(dead_code)]
    pub(crate) fn anonymize_str(&mut self, addr: &str) -> IpAddr {
        // FIX: panicking convenience method is considered unidiomatic
        // | we should decide whether ergonomic is so important or not
        // | (O) -> make this method `pub`
        // | (X) -> move this method to the test module
        let addr: IpAddr = addr
            .parse()
            .expect("input string should be a valid IPv4 or IPv6 address");
        self.anonymize(addr)
    }

    fn anonymize_bin(&mut self, addr: u128, version: u8) -> u128 {
        // REFACTOR: add `anonymize_bytes()`, accepting any `&[u8; N]` where N <= 16
        let (pos_max, ext_addr) = match version {
            4 => (32, addr << 96),
            6 => (128, addr),
            _ => unreachable!(),
        };

        // REFACTOR: rewrite the for loop and `fold()` into something more clean and efficient
        let mut flip_array = Vec::new();
        for pos in 0..pos_max {
            let mask = u128::MAX >> pos;
            let padded_addr = (self.padding & mask) | (ext_addr & !mask);
            let padded_bytes = padded_addr.to_be_bytes();

            let encrypted = self.encrypter.encrypt(&padded_bytes);
            flip_array.push(encrypted[0] >> 7);
        }
        let result = flip_array
            .into_iter()
            .fold(0u128, |acc, x| (acc << 1) | (x as u128));

        addr ^ result
    }

    fn format_ip(addr: u128, version: u8) -> IpAddr {
        match version {
            4 => IpAddr::V4(Ipv4Addr::from((addr & 0xFFFFFFFF) as u32)),
            6 => IpAddr::V6(Ipv6Addr::from(addr)),
            _ => unreachable!(),
        }
    }
}
