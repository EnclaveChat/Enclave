# The foundation's files

Put the two files the foundation publishes here, unchanged:

- `foundation.pub`: the foundation's public key (also built into every
  client). The witness uses it to check the list.
- `server-list.bin`: the current signed server list. The server serves it
  to clients, and the witness witnesses the logs it names. Replace it when
  the foundation publishes a new one; both re-read it on their own.

Both are public. Nothing secret belongs in this directory.
