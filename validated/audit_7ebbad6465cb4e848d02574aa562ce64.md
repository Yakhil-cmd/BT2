[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** types/src/chain_id.rs (L89-96)
```rust
    /// Returns true iff the chain ID matches the given named chain
    fn matches_named_chain(&self, expected_chain: NamedChain) -> bool {
        if let Ok(named_chain) = NamedChain::from_chain_id(self) {
            named_chain == expected_chain
        } else {
            false
        }
    }
```

**File:** types/src/chain_id.rs (L140-149)
```rust
impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            NamedChain::from_chain_id(self)
                .map_or_else(|_| self.0.to_string(), |chain| chain.to_string())
        )
    }
}
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L138-138)
```text
        assert!(chain_id::get() == chain_id, error::invalid_argument(PROLOGUE_EBAD_CHAIN_ID));
```
