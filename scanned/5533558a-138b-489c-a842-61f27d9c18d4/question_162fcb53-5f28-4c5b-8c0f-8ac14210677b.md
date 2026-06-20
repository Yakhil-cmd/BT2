[File: 'rs/rosetta-api/common/rosetta_core/src/response_types.rs -> Scope: Medium'] [Function: ConstructionCombineResponse / handle_construction_combine (icrc1/src/construction_api/utils.rs:352-393)] Can an unprivileged API client send a ConstructionCombineRequest where the unsigned_transaction hex string is valid hex but decodes to CBOR that deserializes into a UnsignedTransaction with envelope_contents.len() != signatures.len() after the length check passes due to duplicate

```python
questions = [
