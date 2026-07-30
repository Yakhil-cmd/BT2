[1](#0-0) [2](#0-1)

### Citations

**File:** crates/sui-core/src/jsonrpc_index.rs (L56-89)
```rust
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct CoinIndexKey2 {
    pub owner: SuiAddress,
    pub coin_type: String,
    // the balance of the coin inverted `!coin.balance` in order to force sorting of coins to be
    // from greatest to least
    pub inverted_balance: u64,
    pub object_id: ObjectID,
}

impl CoinIndexKey2 {
    pub fn new_from_cursor(
        owner: SuiAddress,
        coin_type: String,
        inverted_balance: u64,
        object_id: ObjectID,
    ) -> Self {
        Self {
            owner,
            coin_type,
            inverted_balance,
            object_id,
        }
    }

    pub fn new(owner: SuiAddress, coin_type: String, balance: u64, object_id: ObjectID) -> Self {
        Self {
            owner,
            coin_type,
            inverted_balance: !balance,
            object_id,
        }
    }
}
```

**File:** crates/sui-core/src/jsonrpc_index.rs (L260-260)
```rust
    coin_index_2: DBMap<CoinIndexKey2, CoinInfo>,
```
