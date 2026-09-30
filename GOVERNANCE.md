# Governance

## Stewardship

Enclave is intended to be stewarded by a non-profit foundation (jurisdiction to
be chosen with counsel; Switzerland or the Netherlands preferred). Until it is
formed, the maintainers listed in `MAINTAINERS` act for the project.

## Decisions

* Day-to-day changes: pull requests reviewed by at least one maintainer.
* Protocol and cryptography changes: an RFC in `docs/rfcs/`, open for comment
  for at least 30 days, approved by the crypto working group.
* Security fixes may skip the comment period and are documented afterwards.

## Releases

Releases are signed with a 2-of-3 threshold of maintainer keys (each
SLH-DSA-SHAKE-256s + Ed448) held on offline hardware in at least two
jurisdictions, and logged in a public transparency log.

## Commitments

* No client-side scanning and no key escrow, ever. If a jurisdiction requires
  either, Enclave withdraws from that jurisdiction's app store.
* No telemetry and no analytics.
* An annual transparency report.

## Trademark

Forks are welcome under the license but must use a different name and icon.
