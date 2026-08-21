# Q2609: nibble boundary in shard_tries::delayed_receipt_key_decode_shard_uid

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling keys whose lengths hit odd/even nibble boundaries, drive `core/store/src/trie/shard_tries.rs::delayed_receipt_key_decode_shard_uid` to cause a mismatch between key encoding and decoding, breaking the invariant that nibble encoding round-trips exactly for every key length, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `core/store/src/trie/shard_tries.rs` -> `delayed_receipt_key_decode_shard_uid`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: keys whose lengths hit odd/even nibble boundaries
- Exploit idea: cause a mismatch between key encoding and decoding
- Invariant to test: nibble encoding round-trips exactly for every key length
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: add a proptest/invariant test that randomises the inputs and asserts the accounting identity holds for every generated case
