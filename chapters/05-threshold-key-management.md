# Threshold Decryption Networks and Key Management

Every confidentiality guarantee in an FHE chain ends at the key management service (KMS). The global FHE secret key decrypts every ciphertext ever posted. No single party should hold it, so platforms split it among *n* nodes so that any *t* of them can decrypt and fewer than *t* learn nothing. This chapter covers what that means in practice, what can go wrong, and what to check. Threshold *decryption* for FHE is less mature in production than threshold *signing* for wallets, so lessons from threshold-ECDSA audits are the best evidence available.

## What the KMS does

| Function | Description | Failure impact |
|---|---|---|
| Distributed key generation (DKG) | Nodes jointly create the FHE key pair; each keeps a share of the secret key; public, evaluation and bootstrapping keys are published | A biased or leaked DKG compromises everything that follows |
| Threshold decryption | On ACL-approved requests, *t* nodes produce partial decryptions that combine into the cleartext, plus signatures | Wrong output, or decryption of unauthorised handles |
| Re-encryption | Decrypt-and-re-encrypt under a user key without revealing the cleartext to nodes, ideally | Plaintext exposure to nodes or the relayer |
| Key rotation / resharing | Change the node set or refresh shares | Old shares remain valid; departed operators keep power |
| Attestation | Some designs run nodes in TEEs or prove correct behaviour | False sense of security if attestation is not verified |

Zama's protocol overview describes its KMS as a threshold MPC network that "generates and rotates FHE keys and handles secure, verifiable decryption". Check the current threshold, node operators and whether nodes also run in secure enclaves. Treat these as facts to verify for each deployment, not constants.

## Why threshold FHE decryption is subtle

Threshold decryption of LWE ciphertexts has a problem that threshold RSA or ECDSA does not: each partial decryption includes the node's share times public data, *plus noise*. If nodes publish partial decryptions with too little added noise, observers can learn information about the key shares over many decryptions. The usual fix is "noise flooding": add large fresh noise to each partial result. Peikert's *A Decade of Lattice Cryptography* (2016) mentions noise flooding as a standard proof technique. Engineers must check that the flooding noise is large enough for the number of decryptions the system will ever perform, and that the ciphertext modulus leaves room for it. This is a parameter-review task for a cryptographer, not something to judge by eye.

Second, nodes must check that a request is authorised *before* producing a share. If the ACL check is done by the gateway only and nodes trust it, a compromised gateway can decrypt anything. Ideally each node verifies ACL state itself, for example by reading the host chain through its own light client.

## Lessons from threshold-ECDSA audits

Trail of Bits' *AnySwap Threshold-DSA Security Assessment* (2022) is in our reference library. The review found 27 issues, 12 of high severity. The auditors wrote that the high-severity issues "stem from improper error handling and the improper implementation" of the protocol and "could leak secret data". Several finding titles map directly onto FHE KMS risks:

| AnySwap finding (title) | General lesson for an FHE KMS |
|---|---|
| Weak Fiat-Shamir transformation in Schnorr's zero-knowledge proof | Every proof in DKG or decryption must hash *all* public inputs |
| VSS generates shares from ID coordinates | Secret-sharing evaluation points and share generation must follow the spec exactly |
| Missing checks in NtildeProof verification could lead to Golden Shoe attack | Verify every parameter another node supplies; malicious parameters can extract shares |
| Missing domain separation in various hash computations | Separate hash domains per protocol step and session |
| Unhandled errors in cryptographically sensitive operations | Fail closed; never continue after a failed check |
| Paillier modulus is not proved to be square-free | Proofs of well-formedness for every key a peer contributes |

The protocols differ, but the failure pattern is the same: complex multi-party cryptography is implemented once, then under-tested on the malicious-peer paths. See **mpc-wallet-security** for the signing side and **crypto-implementation-testing** for test methods.

## Operational key management

The DKMS Requirements Report (Reed et al., DHS S&T, 2017), written for decentralised identity, measured its design against NIST SP 800-130 and stressed recovery, rotation and compromise handling for keys with no central authority. The same headings apply to an FHE KMS:

- **Node diversity.** Are operators independent organisations in different jurisdictions and clouds? Five nodes on one cloud account are one node.
- **Share storage.** HSM, TEE, or plain disk? Who can image the machine?
- **Resharing.** When an operator leaves, are shares refreshed so that the old share becomes useless? Without proactive resharing, departed operators accumulate.
- **Threshold choice.** A low *t* weakens confidentiality; a high *t* weakens liveness, because decryptions stall if nodes go offline. Write down both failure modes.
- **Key lifetime.** Ledger ciphertexts are permanent. A key compromise in ten years exposes today's data. Ask about rotation (re-encrypting state under a new key) and its cost.
- **Governance.** Who can add nodes or change *t*? A governance takeover (see **governance-attack-engineering**) that adds attacker nodes can reach the threshold.
- **Monitoring.** Is every decryption logged with the request, ACL proof and nodes involved, so unauthorised decryptions can be detected after the fact?

## Worked example

*Execution status: Not executed in this book's CI; verify locally. Uses only public documentation and a local simulation.*

1. From the platform's docs, record *n*, *t*, the operator list and whether nodes run in TEEs. Note the date you checked.
2. Implement Shamir secret sharing in Python (or use a vetted library) for a toy 3-of-5 split of a random integer. Confirm any three shares reconstruct and any two do not.
3. Simulate operator churn: replace two operators without resharing, and show that a coalition of two old and one current operator still reconstructs the secret. Then implement resharing (each remaining holder re-shares its share) and show the old shares no longer combine.
4. Map each AnySwap finding title in the table to a test you would write for the platform's KMS repository. Record which tests already exist.
5. Write a one-page summary of the residual risk: "If *t* nodes collude, the following data becomes readable…"

## Common pitfalls

- Assuming the KMS checks the ACL itself when only the gateway does.
- Counting nodes rather than independent operators.
- No proactive resharing when operators change.
- Ignoring the permanent exposure of historic ciphertexts after a future key compromise.
- Treating TEE attestation as present without checking that someone verifies it.

## Exercises

1. Complete the Shamir churn simulation and write up the resharing protocol you used.
2. For a chosen platform, list who can change the KMS node set and through which contract or process.
3. Draft monitoring rules that alert when decryption volume, requester mix or node participation changes unexpectedly.

## Further reading

- Trail of Bits, AnySwap Threshold-DSA security assessment (2022).
- Reed et al., *DKMS Requirements Report*, DHS S&T SBIR deliverable (2017).
- Chris Peikert, *A Decade of Lattice Cryptography* (2016), on noise flooding.
- NIST, Multi-Party Threshold Cryptography project: <https://csrc.nist.gov/projects/threshold-cryptography>
