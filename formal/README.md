# Formal models

Symbolic (Dolev–Yao) models in ProVerif. Each query is preceded by the result it must give, as `(* expect: true *)` or `(* expect: false *)`, and `cargo xtask proverif` checks every result in every model against those notes (CI runs it with Ubuntu's `proverif` package; locally, set `PROVERIF` to the binary). An `expect: false` query is a deliberate sanity check: it shows the model can find the attack that the design is meant to prevent, so the matching `true` result means something.

| Model | What it shows | Result |
|---|---|---|
| `proverif/eqxdh.pv` | EQXDH (`docs/04-eqxdh.md`): the session key is secret in both directions; Bob accepts only keys Alice derived for him, and Alice accepts only the reply key Bob derived for her, each once (injective agreement) | 4 queries hold |
| `proverif/eqxdh_fs.pv` | Forward secrecy: after the sessions, every long-term key and the signed prekeys leak (one-time prekeys were deleted); what was sent stays secret | 2 queries hold |
| `proverif/eqxdh_quantum.pv` | PLAN D12's "all KEMs broken" lemma: the attacker takes discrete logs and opens every ML-KEM and McEliece ciphertext. A session whose PSK came from an in-person scan stays secret; the same session without a PSK does not | secret with PSK; attack found without |
| `proverif/lockstep_pcs.pv` | Lockstep post-compromise security (`docs/05-ratchet.md`): after the root key leaks to a quantum attacker, one round trip it sees but does not alter heals the session through the ML-KEM step; an X448-only step does not | heals with ML-KEM; attack found with X448 alone |
| `proverif/group_macs.pv` | Group MAC vectors (`docs/07-groups.md` §3): a compromised member, holding the group's epoch keys, can't make another member accept a message as coming from a third | holds; the sanity query finds the member sending as themselves |

## What the models abstract

- **Primitives are ideal.** KEMs open only with the secret key, KMAC256 is a random oracle, EnclaveSeal is authenticated encryption, X448 is Diffie–Hellman with the usual exponent equation. Computational proofs of EnclaveCombine and EnclaveSeal (CryptoVerif or EasyCrypt) are separate work and not done.
- **Prekey signatures** are replaced by an authenticated public channel for Bob's keys; the composite and SLH-DSA signatures on them are not modelled.
- **Identity sealing** in EQXDH stage 1 hides who initiates; ProVerif's secrecy queries don't express that property, so the model omits it.
- **The ratchet** is reduced to one post-compromise step, not the full Lockstep state machine, its skipped keys or its counters. Replay protection is not modelled anywhere.
- **Group rekeys** (the exporter broadcast) and the state hash chain are not modelled; `group_macs.pv` covers message authentication only.
- **Deniability** needs equivalence queries (the observational kind) and is not modelled yet.

The models are written from the specification and checked by hand against the code; nothing extracts them from the Rust source, so they can drift. A change to EQXDH, the ratchet's PQ step or group authentication must update the matching model.

## Not done

Tamarin models (the plan names both tools), the braid fallback (two KEMs, then McEliece mid-session), device linking, the 72-hour guard, the full ratchet, deniability, and the computational proofs.
