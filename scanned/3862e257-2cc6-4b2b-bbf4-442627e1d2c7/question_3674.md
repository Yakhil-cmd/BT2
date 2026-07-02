# Q3674: shred_receiver_addresses Replay-blocking shred pattern

## Question
Can a malicious shred stream reaching `validator/src/shred_receiver_addresses.rs::push_unique_addr` force honest nodes into a stuck or self-conflicting ledger state that stops them from confirming new transactions?

## Target
- File/function: validator/src/shred_receiver_addresses.rs::push_unique_addr
- Entrypoint: malicious shred or block data from a peer below consensus threshold
- Attacker controls: shred fields, coding/data mix, duplication, ordering, ancestry hints, and signatures
- Exploit idea: Look for poison entries, unresolvable duplicate handling, or repair/replay interactions that leave the ledger permanently non-progressing.
- Invariant to test: Invalid or adversarial shred patterns must be quarantined without permanently halting transaction confirmation.
- Expected Immunefi impact: Critical. Network not being able to confirm new transactions (total network shutdown)
- Fast validation: Inject the adversarial shred schedule in local cluster tests and assert nodes recover to continue replay and confirmation.
