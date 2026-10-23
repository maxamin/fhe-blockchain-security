# FHE Mechanisms and the Encrypted-Contract Threat Model

Fully homomorphic encryption (FHE) lets someone compute on data they cannot read. Chris Peikert's survey *A Decade of Lattice Cryptography* (2016) gives the textbook definition: given a ciphertext encrypting a value µ, anyone can compute a ciphertext encrypting f(µ) for any efficiently computable f, "without ever needing to decrypt the data or know the decryption key". The idea dates from 1978; Gentry built the first plausible scheme in 2009. Jean-Philippe Aumasson's *Serious Cryptography* (2017) describes FHE as cryptography's holy grail and also warns that it is very slow. Both points matter on a blockchain, where every operation costs gas and every node replays the computation.

## Lattices, noise and bootstrapping

Every practical FHE scheme today rests on Learning With Errors (LWE) or its ring variant. A ciphertext hides the message under a random linear combination of the secret key plus a small error term, the **noise**. Decryption removes the linear part and rounds the noise away. Peikert's survey makes the key point for engineers: "homomorphic operations still always increase the error rate of a ciphertext". Additions add the noise terms together. Multiplications multiply them. Once the noise passes half of the scaling factor, rounding gives the wrong answer and decryption fails without any warning.

**Bootstrapping** is Gentry's fix. The scheme evaluates its own decryption circuit homomorphically, using an encryption of the secret key (the bootstrapping key). The output encrypts the same message with fresh, small noise. It is expensive, but it removes the depth limit of a "levelled" scheme. It needs a "circular" encryption of the key under itself, which Peikert notes is an extra assumption beyond plain LWE.

## The three scheme families you will meet

| Family | Plaintext model | Strength | Typical blockchain use |
|---|---|---|---|
| TFHE / FHEW | Small integers or bits; programmable bootstrapping evaluates a lookup table while it refreshes noise | Exact results, cheap comparisons and branch-free selects, unlimited depth | fhEVM-style encrypted integers (`euint8`…`euint256`), comparisons, `select` |
| BFV / BGV | Vectors of integers mod t (SIMD "slots") | Exact batched arithmetic | Batched tallies, encrypted voting, private set operations |
| CKKS | Approximate real or complex numbers | Fast fixed-point arithmetic, ML inference | Off-chain analytics; rarely used for on-chain balances because results are approximate |

Smart contracts need exact comparisons (`balance >= amount`). TFHE's programmable bootstrapping makes these practical, so most encrypted-EVM designs use a TFHE variant. If a project uses CKKS for anything that touches value, ask how it bounds the approximation error.

## What changes when state is encrypted

On a normal chain all state is public, so there is nothing to keep secret. In an FHE chain:

- Balances, bids, votes and other values are stored as **ciphertext handles**: references to ciphertexts held off-chain or in special storage.
- Contract logic runs on handles. Heavy FHE work is often pushed to off-chain **coprocessors**, and the chain records only what to compute.
- Someone must eventually **decrypt** values, such as an auction winner or a withdrawal amount. Since nobody should hold the whole key, a **threshold network** (often called a KMS) holds key shares and decrypts only when an **access-control list (ACL)** allows it.

The ESORICS 2017 DPM/CBT workshop proceedings (LNCS 10436, 2017) separate partially, somewhat and fully homomorphic cryptosystems; if a contract only needs encrypted addition, a cheaper additively homomorphic scheme may do.

## Threat model

```mermaid
flowchart LR
  U[User / wallet] -- encrypted input + proof --> C[Host contract]
  C -- symbolic ops on handles --> CP[Coprocessor(s)]
  C -- ACL grants --> ACL[(ACL contract)]
  C -- decryption request --> GW[Gateway / relayer]
  GW --> KMS[Threshold KMS]
  KMS -- signed plaintext / reencryption --> GW --> C
  A1((Malicious contract)) -.-> C
  A2((Observer of gas, reverts, events)) -.-> C
  A3((Colluding KMS nodes)) -.-> KMS
  A4((Faulty coprocessor)) -.-> CP
```

| Adversary | Goal | Main question for the auditor |
|---|---|---|
| Any chain observer | Learn plaintexts from public side information | Does control flow, gas, revert status, event data or timing depend on secret values? |
| Malicious contract or user | Obtain decryption rights to someone else's ciphertext | Can a handle be copied, replayed or forwarded to a contract that will decrypt it? |
| Malicious input submitter | Inject a ciphertext they cannot open, or reuse someone else's | Is every external ciphertext checked with a proof of knowledge bound to the sender and contract? |
| Coprocessor operator | Return wrong results or skip work | Are results verified by redundancy, consensus or proofs? |
| t-of-n KMS nodes | Decrypt everything, or refuse service | What is t? How are shares generated, rotated and attested? |
| Protocol governance | Change the ACL logic or the keys | Who can upgrade ACL, gateway and KMS contracts? |

Two assumptions are easy to miss. First, **FHE hides values, not access patterns**: the function called, the storage slot changed and the recipient address stay public unless the design hides them. Second, **the decryption network is the root of trust for confidentiality**. If enough KMS nodes collude, all historic ciphertexts become readable, because ledger data never expires.

For related material, see **privacy-protocol-security** (ZK-based privacy) and **mpc-wallet-security** (threshold key handling).

## Worked example

*Execution status: run locally with Python 3.13 (standard library only); the output below was observed. The parameters are deliberately insecure and for teaching only.*

A toy LWE scheme shows why noise budget is a correctness issue and why encrypted arithmetic wraps. Save as `toy_lwe.py`:

```python
import random
random.seed(1)
n, q, t = 32, 2**15, 16
delta = q // t
s = [random.randrange(q) for _ in range(n)]
def enc(m, sigma=20):
    a = [random.randrange(q) for _ in range(n)]
    e = round(random.gauss(0, sigma))
    return a, (sum(x*y for x, y in zip(a, s)) + delta*m + e) % q
def add(c1, c2):
    return [(x+y) % q for x, y in zip(c1[0], c2[0])], (c1[1]+c2[1]) % q
def phase(c): return (c[1] - sum(x*y for x, y in zip(c[0], s))) % q
def dec(c): return round(phase(c) / delta) % t
def noise(c, m):
    d = (phase(c) - delta*m) % q
    return d if d < q//2 else d - q
c, m = enc(3), 3
for k in range(1, 9):
    c = add(c, c); m = (2*m) % t
    print(k, "expected", m, "decrypted", dec(c), "noise", noise(c, m), "budget", delta//2)
```

Run `python3 -I toy_lwe.py`. In our run the noise doubled each step (−10, −20, … −640). After the eighth doubling it reached −1280, beyond the ±1024 budget, and decryption returned 15 instead of 0. Note also that 3 × 16 = 48 decrypted as 0: plaintext arithmetic is modulo t, which is the same wrap-around behaviour that encrypted integer types show in real platforms.

## Common pitfalls

- Treating "encrypted" as "private". Function selectors, call graphs, storage writes and gas usage stay public.
- Assuming encrypted integers revert on overflow. Most platforms wrap silently, so a revert would leak information.
- Ignoring the KMS threshold and the long life of ledger data when judging confidentiality.
- Using approximate CKKS results where every node must agree on exact values.
- Reasoning only about the cipher and skipping the gateway, relayer and ACL contracts.

## Exercises

1. Change `sigma` and `q` in the toy script and find how many doublings each setting survives. Plot noise against operations.
2. Draw a data-flow diagram for a confidential ERC-20 transfer on a platform of your choice. Mark every point where plaintext or metadata leaves the encrypted domain.
3. List three contract features (for example, "revert if insufficient balance") that would leak a secret bit, and propose a branch-free version of each.

## Further reading

- Chris Peikert, *A Decade of Lattice Cryptography* (2016), Chapter 6 (FHE and bootstrapping).
- Jean-Philippe Aumasson, *Serious Cryptography* (No Starch, 2017), section on fully homomorphic encryption.
- Zama protocol documentation: <https://docs.zama.org/protocol>
- TFHE-rs library: <https://github.com/zama-ai/tfhe-rs>; OpenFHE (BFV/BGV/CKKS): <https://openfhe.org>
- See **crypto-implementation-testing** for testing lattice libraries.
