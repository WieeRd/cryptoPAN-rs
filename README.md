# cryptoPAn-rs

`cryptoPAn-rs` is a Rust version of the Crypto-PAn (Prefix-preserving Anonymization) algorithm. It offers a fast, secure, and scalable network traffic analysis and privacy protection solution. The Crypto PAn algorithm, allows for the prefix-preserving anonymization of IP addresses, ensuring that the anonymized addresses maintain the same prefix as the original addresses for any given prefix length, which is crucial for network analysis tasks.
You can refer to the [Wikipedia page](https://en.wikipedia.org/wiki/Crypto-PAn).

## Backend

Currently only supports OpenSSL as a backend.

- [ ] Support RustCrypto's AES implementation as a backend 

## Features

- **Prefix-Preserving Anonymization:** Anonymizes IP addresses while preserving their subnet structure.
- **High Performance:** Implemented in Rust for speed and efficiency.
- **Cross-Platform:** Can be used on various platforms where Rust is supported.

## Getting Started

### Prerequisites

Before you begin, please make sure you have Rust, and OpenSSL installed on your machine. 


<!-- ### Installation -->

<!-- To use `cryptoPAN-rs` in your project, add the following to your `Cargo.toml` file: -->

<!-- ```toml -->
<!-- [dependencies] -->
<!-- cryptoPAN-rs = { git = "https://github.com/SkuldNorniern/cryptoPAN-rs" } -->
<!-- ``` -->

## Contributing

Welcome to `cryptoPAn-rs`! Please submit pull requests or open issues to report bugs, request features, or suggest improvements.

## License

`cryptoPAn-rs` is released under the Apache 2 License. See the [LICENSE](LICENSE) file for details.
