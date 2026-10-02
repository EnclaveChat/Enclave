# Acceptable Use Policy (template)

*Replace everything in [brackets].*

You may not use an account on **[domain]** to:

- send unsolicited bulk messages or message requests (spam);
- harass, threaten or impersonate people;
- share content that is illegal in [jurisdiction], including child sexual
  abuse material;
- attack the server or the network (flooding, abusing proof of work,
  probing for vulnerabilities outside our security policy).

## How we enforce it

We cannot read content, so we act only on what users report to us. A
report is sent from the app and contains what the reporter chose to
include. Reports from off-the-record chats can't prove who wrote the
quoted messages; we take that into account.

Our only enforcement tools are the ones the software provides
(`docs/13-operators.md` §1):

| We may | Effect |
|---|---|
| Rate-limit or raise proof-of-work effort | Slower sending |
| Delete a reported file | It no longer downloads |
| Disable a reported inbox or request inbox | Writes to it are refused |
| Tombstone a username | Anyone looking it up sees it was withdrawn |
| Stop new registrations | New accounts go elsewhere |

We do not, and cannot, suspend "accounts" by identity: there is no account
record on the server to suspend.
