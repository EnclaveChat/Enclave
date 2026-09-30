# RFC 0000: Template

Status: Draft (M0) · Normative

This is the template for Enclave RFCs. Copy it to `docs/rfcs/NNNN-short-title.md`, where `NNNN` is the next free number, and fill in every section. Delete the guidance text in italics.

## Process (normative)

1. **When an RFC is required.** Any change to: a primitive, suite, or construction in `02-cryptography.md`; a derivation or label in `02b-key-schedule.md` or the crypto-owned rows of `label-registry.md`; any wire or stored layout in `08-envelope.md`; the protocol behavior in `03`–`07`, `09`–`11`; the threat model or leakage matrix; the cover-traffic profiles; the licensing or governance rules. Editorial fixes that change no behavior do not need an RFC.
2. **Filing.** Open a pull request that adds the RFC file with status `Proposed`. The PR description links the affected spec sections.
3. **Comment period.** At least **30 days** of public comments from the date the PR is opened.
4. **Review.** The crypto working group reviews every RFC that touches cryptography, protocol, or metadata. At least two members must approve. Other RFCs need two maintainer approvals.
5. **Decision.** The RFC is marked `Accepted`, `Rejected`, or `Withdrawn`, with a one-paragraph rationale. Accepted RFCs are merged together with the spec changes they make (or those changes follow in a PR that links the RFC).
6. **Implementation.** Code that implements an RFC references it in the PR. Changes to wire formats bump the version or suite and follow `19-ops.md` §4 (90-day overlap; 12 months of dual support for suite retirement).
7. **Security embargo.** An RFC that fixes an undisclosed vulnerability may be reviewed privately under `SECURITY.md` and published when the fix ships.

---

# RFC NNNN: *Title*

- **Status:** Proposed | Accepted | Rejected | Withdrawn | Superseded by RFC NNNN
- **Author(s):** *name, contact*
- **Created:** *YYYY-MM-DD*
- **Comment period ends:** *YYYY-MM-DD (≥ 30 days after Created)*
- **Affects:** *list of spec files and sections, e.g. `08-envelope.md` §5, `label-registry.md` §2.5*
- **Crypto WG review required:** yes | no

## Summary

*One paragraph: what changes and why.*

## Motivation

*The problem, with evidence (measurements, attacks, user research, platform changes). Link red-team rows and PLAN decisions it touches.*

## Specification

*The normative change, written as it will appear in the spec (MUST/SHOULD/MAY). Include exact byte layouts with offsets and sums, pseudocode, new labels with kind and output length, and error handling.*

## Security and privacy analysis

- *Effect on each goal in `01-threat-model.md` §3.*
- *Effect on the leakage matrix (`01-threat-model.md` §4): what any observer learns that it did not before.*
- *New or changed red-team rows (`redteam-matrix.md`), with residuals and test names.*
- *Formal-model impact: which models must be updated (`20-assurance.md` §2).*

## Compatibility and migration

*Version or suite changes, overlap period, behavior of old and new clients, database migrations.*

## Costs

*Bytes per unit, data per hour/day per profile (`math/cover-traffic.md`), CPU, battery, server load.*

## Alternatives considered

*Each alternative and why it was not chosen.*

## Test plan

*New vectors, invariants, simulations, traffic-shape tests.*

## Open questions

*Anything the comment period should resolve.*
