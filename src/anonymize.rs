use std::net::IpAddr;

/// Merges 2 arrays of same length into 1 using a given closure.
///
/// Basically `Iterator::zip(a, b).map(f)` if `a` and `b` were iterators.
fn zip_with<F, const N: usize>(a: &[u8; N], b: &[u8; N], f: F) -> [u8; N]
where
    F: Fn(u8, u8) -> u8,
{
    std::array::from_fn(|i| unsafe {
        let a = a.get_unchecked(i);
        let b = b.get_unchecked(i);
        f(*a, *b)
    })
}

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
    padding: [u8; 16],
}

impl<E: Encrypter> Anonymizer<E> {
    pub fn new(key: &[u8; 32]) -> Self {
        let enc_key: &[u8; 16] = key[..16].try_into().unwrap();
        let pad_key: &[u8; 16] = key[16..].try_into().unwrap();
        let encrypter = Encrypter::from_key(enc_key);

        Self::with_encrypter(encrypter, pad_key)
    }

    pub fn with_encrypter(encrypter: E, padding: &[u8; 16]) -> Self {
        let padding = encrypter.encrypt(padding);
        Self { encrypter, padding }
    }

    pub fn anonymize(&self, addr: IpAddr) -> IpAddr {
        match addr {
            IpAddr::V4(addr) => {
                let mut bytes = [0; 16];
                bytes[..4].copy_from_slice(&addr.octets());

                let anonymized = self.anonymize_bytes(&bytes, 32);
                let truncated: [u8; 4] = anonymized[..4].try_into().unwrap();

                truncated.into()
            }
            IpAddr::V6(addr) => {
                let bytes = addr.octets();
                self.anonymize_bytes(&bytes, 128).into()
            }
        }
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
    pub(crate) fn anonymize_str(&self, addr: &str) -> IpAddr {
        // FIX: panicking convenience method is considered unidiomatic
        // | we should decide whether ergonomic is so important or not
        // | (O) -> make this method `pub`
        // | (X) -> move this method to the test module
        let addr: IpAddr = addr
            .parse()
            .expect("input string should be a valid IPv4 or IPv6 address");
        self.anonymize(addr)
    }

    fn anonymize_bytes(&self, bytes: &[u8; 16], n_bits: usize) -> [u8; 16] {
        if n_bits > 128 {
            panic!("`n_bits` should be less than 128");
        }

        let mut mask: [u8; 16] = [0b11111111; 16];
        let mut result: [u8; 16] = [0; 16];

        for i in 0..n_bits {
            // padded = (bytes & !mask) | (self.padding & mask)
            // first `i - 1` bits from `bytes`, the rest from `padding`
            let padded = {
                let bytes = zip_with(&mask, &bytes, |m, b| !m & b);
                let padding = zip_with(&mask, &self.padding, |m, p| m & p);
                zip_with(&bytes, &padding, |b, p| b | p)
            };
            let encrypted = self.encrypter.encrypt(&padded);

            result[i / 8] = (result[i / 8] << 1) | (encrypted[0] >> 7);
            mask[i / 8] >>= 1;
        }

        zip_with(&bytes, &result, |b, r| b ^ r)
    }
}
