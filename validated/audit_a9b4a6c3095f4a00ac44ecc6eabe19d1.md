Let me analyze the external bug's core invariant and search for nearcore analogs systematically.

The external bug is about **mid-operation state inconsistency**: between a pre-hook and post-hook, the system is in a partially-updated state, and an unprivileged actor can interact with it to exploit the discrepancy.

For nearcore, the analog invariant would be: **receipt/state causality** — can an unprivileged user interact with partially-updated state between two steps of an atomic operation?