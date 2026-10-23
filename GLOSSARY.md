# Glossary

- **FHE (fully homomorphic encryption):** encryption that allows arbitrary computation on ciphertexts.
- **LWE / RLWE:** Learning With Errors and its ring variant; the hardness assumptions behind modern FHE.
- **Noise (error):** small random term in an LWE ciphertext; grows with each operation and breaks decryption if it exceeds the budget.
- **Bootstrapping:** homomorphically evaluating decryption to refresh noise; enables unlimited computation depth.
- **Programmable bootstrapping:** TFHE technique that applies a lookup table while bootstrapping.
- **TFHE:** FHE scheme family operating on small integers with fast bootstrapping; used by most encrypted-EVM designs.
- **BFV / BGV:** exact integer FHE schemes with SIMD batching.
- **CKKS:** approximate-arithmetic FHE scheme for real numbers.
- **Ciphertext handle:** short on-chain reference to a ciphertext stored off-chain or in special storage.
- **ACL (access-control list):** on-chain record of which addresses may use or decrypt each handle.
- **Transient allowance:** ACL grant valid only for the current transaction (EIP-1153 transient storage).
- **Coprocessor:** off-chain service that executes FHE operations requested by host contracts.
- **Gateway / relayer:** services that coordinate requests between users, host chains, coprocessors and the KMS.
- **KMS (key management service):** threshold network that holds FHE secret-key shares and performs decryption.
- **ZKPoK:** zero-knowledge proof of knowledge; proves the submitter knows the plaintext of an encrypted input.
- **Decryption oracle:** any path that lets an unauthorised party learn a function of a secret value.
- **Noise flooding:** adding large fresh noise to partial decryptions so they reveal nothing about key shares.
- **Resharing:** refreshing secret shares so old shares become useless after operator changes.
