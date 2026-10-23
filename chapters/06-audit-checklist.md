# Auditing Encrypted Contracts: A Checklist

This chapter turns the previous five into a review procedure. Use it for confidential tokens, sealed-bid auctions, private voting and any contract that stores encrypted state on an FHE platform. As always: audit only code you are authorised to review, test on local devnets or testnets, and report findings through the project's disclosure channel.

## Scoping questions

Before reading code, answer these in writing:

1. **What must stay secret, from whom, and for how long?** "Balances, from everyone except the owner, forever" sets a different bar from "bids, until the auction closes".
2. **What becomes public on purpose?** Winners, totals, settlement amounts. Each intended disclosure is a starting point for inference.
3. **Which platform version?** APIs (`fromExternal` versus `asEuint`, decryption callbacks versus signature checks) differ between releases. Pin the library version and read that version's docs.
4. **Who runs the coprocessors and KMS, with what threshold?** Record *n*, *t* and operators, with the date.
5. **What can be upgraded, and by whom?** Include the ACL contract, gateway and KMS configuration, not only the application.

## Checklist

### A. Inputs

- [ ] Every user-supplied ciphertext enters through the platform's proof-checked path (`externalEuint*` + proof → `fromExternal` or equivalent).
- [ ] Functions that accept already-encrypted handles (`euint*`) check `isSenderAllowed` (or equivalent) for each one.
- [ ] Inputs encrypted for one contract cannot be replayed through an intermediary; nonces or context binding exist where intermediaries are used.
- [ ] No de-duplication relies on hashing proof bytes.

### B. ACL

- [ ] After every operation that replaces a stored handle, `allowThis` is called (liveness).
- [ ] Every `allow` to another address is listed with a reason; permanent grants to contracts are justified.
- [ ] Helper contracts receiving handles check their caller and use transient grants.
- [ ] No contract holding grants can make arbitrary external calls or `delegatecall` to untrusted code.
- [ ] Transient permissions are cleared where bundles, multicalls or account-abstraction user operations share a transaction.
- [ ] Migrations re-grant what is needed and leave no grants to retired contracts.

### C. Decryption

- [ ] Every public decryption is listed with who triggers it, how often, and on which inputs.
- [ ] No caller-chosen comparison results are made public (comparison oracles).
- [ ] Disclosures happen after finality; two-step reveals where outcomes have value.
- [ ] Decryption results are verified on chain (KMS signatures, handle order), not trusted from a relayer.
- [ ] Callbacks or result submissions are replay-protected and clear request state before external transfers.

### D. Control flow and side channels

- [ ] No `if`, `require` or revert depends on a decrypted secret, except where the leak is intended and documented.
- [ ] Silent failure paths (zero-transfers) feed the *moved* amount, not the requested amount, into later logic.
- [ ] Loops are bounded by public values.
- [ ] Events and storage writes do not differ by secret branch.
- [ ] Encrypted type widths do not leak magnitude.
- [ ] Overflow-sensitive arithmetic is clamped with encrypted comparisons and selects.

### E. Platform and keys

- [ ] Coprocessor results are verified by redundancy, consensus or proofs; the design document says which.
- [ ] KMS nodes verify ACL state themselves, or the gateway's trust is documented.
- [ ] Threshold, operators, share storage, resharing and rotation are documented.
- [ ] Governance over the KMS node set and ACL upgrades is time-locked and monitored.
- [ ] Residual risk if *t* nodes collude is written down for users.

## Severity guidance

| Finding | Typical severity |
|---|---|
| Any user can decrypt another user's balance (ACL laundering, helper oracle) | Critical |
| Logic error from silent zero-transfer (win auction without paying) | Critical or High |
| Comparison oracle needing many transactions | High or Medium, depending on query cost and value |
| Disclosure before finality | Medium to High, depending on value at stake |
| Missing `allowThis` (funds stuck, contract unusable) | High (liveness) |
| Metadata leaks (type width, event shape) | Low to Medium |

## Tooling

FHE-specific static analysis is young. Practical options in 2026:

- **Grep inventories.** `rg -n 'FHE\.(allow|allowTransient|makePubliclyDecryptable|fromExternal|isSenderAllowed)'` gives a quick map of grants, inputs and checks.
- **Custom detectors.** Write Slither or Semgrep rules for "public function takes `euint*` without `isSenderAllowed`" and "`require` on a decrypted value". Test each rule on known-bad and known-good samples before trusting it (see **ai-static-analysis-rule-writing**).
- **Mock-mode tests.** Platform mock modes run FHE in plaintext. They are good for ACL and logic tests, useless for cryptographic claims.
- **AI assistants.** An LLM can draft the grant inventory or propose tests. Treat its output as a lead: verify each claimed issue with a failing test before reporting (see **ai-assisted-audit-playbook**).

## Worked example

*Execution status: Not executed in this book's CI; verify locally against an open-source confidential token you are allowed to test.*

1. Clone the target and pin the FHE library version from its lockfile.
2. Run the inventory grep and paste the results into a table with columns: location, function, handle, grantee, reason, transient?
3. For each public function, mark which checklist items apply and tick or flag them.
4. For each flag, write a mock-mode Hardhat test that demonstrates the issue (for example, Bob decrypting Alice's balance). A finding without a failing test stays a "lead".
5. Write the report: scope, platform version, trust assumptions (KMS, coprocessors), findings with tests, and residual risks.

## Common pitfalls

- Auditing the application and skipping the platform trust assumptions.
- Reporting suspected leaks without a reproducing test.
- Treating a mock-mode pass as evidence of cryptographic security.
- Ignoring inference from intended disclosures.
- Copying API names from old blog posts instead of the pinned version's docs.

## Exercises

1. Apply the checklist to an open-source confidential ERC-20 and produce a findings table.
2. Turn three checklist items into Semgrep rules and measure their false-positive rate on five repositories.
3. Write the "residual risk" paragraph a project should publish for users about its KMS threshold.

## Further reading

- OpenZeppelin, "A Developer's Guide to FHEVM Security" (2025): <https://www.openzeppelin.com/news/a-developers-guide-to-fhevm-security>
- Zama Solidity guides: <https://docs.zama.org/protocol/solidity-guides>
- Trail of Bits, AnySwap Threshold-DSA security assessment (2022), as a model of threshold-crypto findings.
- See **privacy-protocol-security** and **zk-circuit-security** for complementary privacy audits.
