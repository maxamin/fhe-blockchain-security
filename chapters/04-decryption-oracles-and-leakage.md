# Decryption Oracles, Branch Leakage and Side Channels

Encryption protects values at rest and in computation. It does not protect against a contract that *tells* someone what the value is. This chapter covers the ways encrypted contracts leak: through explicit decryption, through control flow, and through side channels such as gas, reverts, events and timing. Jean-Philippe Aumasson's *Serious Cryptography* (2017) defines a side channel as "a source of information that depends on the implementation", with execution time the typical software example. On a public ledger, the implementation is public and every execution is recorded forever, so side channels are easier to measure than on a smart card.

## Decryption oracles

A **decryption oracle** is any path that lets an unauthorised party learn a function of a secret. It does not need to reveal the whole value. One bit per query is enough if queries are cheap.

| Oracle type | Example | Leak per query |
|---|---|---|
| Direct public decryption | Contract makes `balance` publicly decryptable to "show solvency" | Full value |
| Comparison oracle | `isRich(addr)` returns a publicly decryptable `ebool` for `balance > X` | 1 bit; binary search recovers a 64-bit value in about 64 queries |
| Derived-value oracle | Fee or interest handle granted to caller, derived linearly from a victim's amount | Full value after inversion |
| ACL laundering | Victim handle accepted as caller input (Chapter 3) | Full value |
| Reorg race | Value disclosed before finality; chain reorganises and the outcome changes while the secret is already out | Value plus unfair advantage |

The reorg race comes from OpenZeppelin's *A Developer's Guide to FHEVM Security* (2025): an auction made the winner and bid publicly decryptable at once, so a reorg could change the winner after the hidden prize was known. The fix is a two-step reveal that waits for finality.

Ask of every decryption: **who triggers it, how often, on which inputs, and what can they compute from the answer?** A comparison against an attacker-chosen threshold is a decryption oracle with a rate limit of one bit per transaction.

## Branch leakage

The EVM cannot branch on a ciphertext: an `ebool` has no plaintext for `if`. Platforms offer a branch-free select (`FHE.select(cond, a, b)`), and both sides are always computed. That is the right model. Developers then add leaks back in three ways:

1. **Decrypting to branch.** Decrypt the condition, then `if`. The decryption result is public, so the branch outcome is public.
2. **Reverting on encrypted conditions.** "Revert if insufficient funds" tells everyone that the balance was below the amount. For this reason transfers on FHE tokens usually *succeed* and move zero on failure. The OpenZeppelin guide stresses that encrypted arithmetic is intentionally unchecked so that reverts do not leak.
3. **Branch-dependent side effects.** Emitting different events, writing different storage slots, or calling different contracts depending on a decrypted flag.

Silent zero-transfers create a functional bug class of their own. The same guide shows an auction that recorded the *requested* bid amount rather than the amount actually transferred. Because a failing transfer moved zero without reverting, a bidder could win with no funds. Always continue the computation with the amount actually moved.

```solidity
// Branch-free transfer: no revert, no branch on secret
ebool ok = FHE.le(amount, balances[from]);
euint64 moved = FHE.select(ok, amount, FHE.asEuint64(0));
balances[from] = FHE.sub(balances[from], moved);
balances[to]   = FHE.add(balances[to], moved);
// Use `moved`, never `amount`, in later logic
```

## Gas, timing and metadata

- **Gas.** If operation cost depends on a secret (for example, a loop whose bound is decrypted, or an early exit), gas used is a public function of the secret. FHE operations themselves have fixed cost per type, so keep loops bounded by public values and update state with selects inside the loop.
- **Type width.** Using `euint8` for small amounts and `euint64` for large ones leaks magnitude through the type chosen, which is visible in calldata and gas.
- **Timing of decryption requests.** If a protocol requests decryption only when a hidden condition is met, the request event itself leaks the condition.
- **Who interacts.** Recipient addresses, function selectors and call frequency stay public. A confidential token still shows that Alice paid Bob.
- **Integer wrap.** Overflow wraps silently. The OpenZeppelin guide shows a fee computed as `amount × rate` that wrapped to near zero for a huge encrypted amount. Clamp with `FHE.gt` + `FHE.select`.

## Inference over many transactions

Even with no single leak, aggregate public information narrows secrets. If the total supply is public and only two holders exist, one balance reveals the other. If a confidential AMM publishes reserves after each trade, the trade size is the difference. When you review a design, list every value that becomes public (totals, outcomes, winners) and ask what it reveals combined with earlier public values. The privacy-engineering idea of "minimise and hide" in Danezis et al., *Privacy and Data Protection by Design* (ENISA, 2014) applies directly: publish aggregates only when needed, and as coarsely as possible.

## Worked example

*Execution status: Not executed in this book's CI; verify locally. Mock-mode tests check logic only, which is enough for leakage via reverts and branches.*

Build and break a comparison oracle on a local devnet:

1. In the Hardhat template, write `Leaky.sol` with `euint64 secret` and a public function `check(uint64 x)` that computes `FHE.gt(secret, FHE.asEuint64(x))`, marks the result publicly decryptable, and stores the handle.
2. Write a script that runs a binary search: call `check(mid)`, run the public decryption flow, and narrow the range. Count calls until the secret is known. Expect about 64 for a 64-bit value.
3. Add a rate limit (one query per address per day) and repeat with ten test accounts. Note how Sybil accounts defeat per-address limits.
4. Redesign so the function returns an encrypted result only to an ACL-authorised owner via user decryption. Confirm the script no longer works.
5. Separately, make the `transfer` function revert on insufficient balance, and write a test that infers whether a balance exceeds a threshold from the revert alone.

## Common pitfalls

- Exposing an encrypted comparison against caller-chosen input as a public result.
- Reverting on encrypted conditions, or emitting branch-specific events.
- Using the requested amount instead of the moved amount after a silent zero-transfer.
- Loops or early exits bounded by decrypted values.
- Disclosing results before finality.

## Exercises

1. Write the binary-search oracle script and measure the number of transactions and total gas to recover a 32-bit secret.
2. Take an open-source confidential ERC-20 and list every public signal (events, totals, reverts). Estimate what an observer learns about one holder after 100 transfers.
3. Rewrite a sealed-bid auction so that only the winning price, and nothing about losing bids, is ever decrypted.

## Further reading

- OpenZeppelin, "A Developer's Guide to FHEVM Security" (2025): <https://www.openzeppelin.com/news/a-developers-guide-to-fhevm-security>
- Zama guide on branching: <https://docs.zama.org/protocol/solidity-guides/smart-contract/logics/conditions>
- Danezis et al., *Privacy and Data Protection by Design – from policy to engineering* (ENISA, 2014).
- Aumasson, *Serious Cryptography* (2017), side-channel sections.
- See **mev-security-engineering** for ordering and reorg effects.
