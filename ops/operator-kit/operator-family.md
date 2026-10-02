# Your operator family

Every server, witness and call relay you run declares an **operator**
(the name users see) and a **family**. A family is everyone who could be
made to act together: one organization, its subsidiaries, a person and
the company they own, two charities sharing staff and infrastructure, or
operators bound by the same order in the same jurisdiction.

Set both in `.env` (`OPERATOR`, `FAMILY`). They go into every descriptor
you sign, and from there into the foundation's list.

## Why it matters

Enclave's protections against operators rest on independence:

- **Key transparency.** A witness never counts for a log run by its own
  operator, and the foundation lists witnesses from other families, so a
  quorum of cosignatures means organizations that don't answer to each
  other all saw the same log. A hidden family tie turns "two independent
  witnesses" into one.
- **Calls.** Each side of a call picks a relay from a different family,
  so no single operator sees both ends of a call's traffic.
- **The list.** The foundation spreads servers across families and
  jurisdictions when it weighs them for new accounts.

A family that lies about itself defeats all three without breaking any
cryptography. That is why the foundation's code of practice treats a false
family declaration as grounds for removal from the list.

## How to choose

- Use one short, stable identifier (`example-org`), the same for every
  service you run, now and later.
- If you are unsure whether two operators are one family, declare them as
  one. Over-declaring costs some routing choice; under-declaring costs
  users their protection.
- Tell the foundation when ownership, control or hosting changes. It
  updates the list.
