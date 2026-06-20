[File: 'packages/icrc-ledger-types/src/icrc/metadata_key.rs -> Scope: Medium'] [Function: MetadataKey Serialize/Deserialize round-trip / serde cbor ledger state] Can an unprivileged actor, by exploiting the fact that MetadataKey derives serde::Deserialize without validation, cause a ledger canister that deserializes its stable state (Vec<(MetadataKey, StoredValue)>) from CBOR/serde during post-upgrade to silently load invalid MetadataKey values that were stored by a previous version, bypassing the is_valid() check that upgrade() uses to determine require_valid, and then have those invalid keys persist indefinitely in the live ledger state without any warning or rejection? Proof idea: serialize a

```python
questions = [
