### Title
ERC-20 Mirror Tokens Deployed via Legacy Path Report `decimals = 0`, Causing Incorrect Accounting in External Contracts - (File: `engine/src/engine.rs`, `engine-types/src/parameters/connector.rs`, `etc/eth-contracts/contracts/EvmErc20.sol`)

---

### Summary

When a NEP-141 token is bridged to Aurora using the `DeployErc20TokenArgs::Legacy` path, the resulting `EvmErc20`/`EvmErc20V2` mirror token is deployed with `_decimals = 0` instead of the actual NEP-141 token's decimals. This happens because the legacy path passes `None` as metadata, which falls back to `Erc20Metadata::default()` where `decimals` is hardcoded to `0`. Any external EVM contract on Aurora that calls `decimals()` on such a token and uses the result for amount normalization receives a completely wrong value, enabling fund theft or insolvency in downstream DeFi protocols.

---

### Finding Description

`deploy_erc20_token` in `engine/src/contract_methods/connector.rs` handles two variants:

```rust
// engine/src/contract_methods/connector.rs:124-125
DeployErc20TokenArgs::Legacy(nep141) => {
    let address = engine::deploy_erc20_token(nep141, None, io, env, handler)?;
``` [1](#0-0) 

The `None` metadata propagates into `setup_deploy_erc20_input`:

```rust
// engine/src/engine.rs:1327
let erc20_metadata = erc20_metadata.unwrap_or_default();
``` [2](#0-1) 

`Erc20Metadata::default()` is defined as:

```rust
impl Default for Erc20Metadata {
    fn default() -> Self {
        Self {
            name: "Empty".to_string(),
            symbol: "EMPTY".to_string(),
            decimals: 0,   // <-- always 0
        }
    }
}
``` [3](#0-2) 

This `0` is then ABI-encoded and passed to the `EvmErc20` constructor:

```rust
ethabi::Token::Uint(erc20_metadata.decimals.into()),  // 0
``` [4](#0-3) 

The Solidity constructor stores it verbatim:

```solidity
_decimals = metadata_decimals;  // 0
``` [5](#0-4) 

And `decimals()` returns it directly:

```solidity
function decimals() public view override returns (uint8) {
    return _decimals;  // always 0 for legacy-deployed tokens
}
``` [6](#0-5) 

The `WithMetadata` path (added later) correctly fetches the real decimals from the NEP-141 `ft_metadata` call and passes them through `deploy_erc20_token_callback`:

```rust
decimals: metadata.decimals,  // actual NEP-141 decimals
``` [7](#0-6) 

But the legacy path remains active and callable by any NEAR account with no access control guard, as confirmed by the unit test which asserts the default (broken) state:

```rust
assert_eq!(metadata, Erc20Metadata::default());  // decimals == 0
``` [8](#0-7) 

Meanwhile, the bridge mints ERC-20 tokens 1:1 with the raw NEP-141 amount — no decimal scaling is applied:

```rust
pub fn setup_receive_erc20_tokens_input(recipient: &Address, amount: u128) -> Vec<u8> {
    let tail = ethabi::encode(&[
        ethabi::Token::Address(recipient.raw().0.into()),
        ethabi::Token::Uint(amount.into()),  // raw NEP-141 amount, no scaling
    ]);
``` [9](#0-8) 

So a NEP-141 token with 6 decimals (e.g., USDC) bridged via the legacy path produces an ERC-20 that:
- Holds balances in 6-decimal precision (1 USDC = 1,000,000 token units)
- Reports `decimals() == 0` to any caller

---

### Impact Explanation

Any external EVM contract on Aurora (DEX, lending protocol, vault, price oracle) that calls `decimals()` on a legacy-deployed ERC-20 mirror token and uses the result for amount normalization will receive `0`. With `0` decimals, the contract treats 1,000,000 token units as 1,000,000 whole tokens instead of 1 whole token — a 10^6 overvaluation for a 6-decimal asset like USDC, or a 10^24 overvaluation for NEAR (24 decimals). This directly enables:

- **Fund theft**: An attacker deposits a small amount of the overvalued token into a lending protocol, borrows against the inflated collateral value, and walks away with the borrowed funds.
- **Insolvency**: A protocol that prices the token using `decimals()` will have its accounting permanently broken, leading to insolvency.

**Impact: Critical** — direct theft of user funds in any external protocol that integrates a legacy-deployed ERC-20 mirror token.

---

### Likelihood Explanation

- The legacy `deploy_erc20_token` path has no access control; any NEAR account can invoke it.
- The `DeployErc20TokenArgs::deserialize` fallback means old callers passing a bare `AccountId` still trigger the legacy path.
- NEP-141 tokens bridged before `WithMetadata` was introduced are permanently deployed with `decimals = 0` unless `set_erc20_metadata` is called afterward.
- Aurora hosts active DeFi protocols; any that integrate these tokens and read `decimals()` are immediately vulnerable.

**Likelihood: High.**

---

### Recommendation

1. Change `Erc20Metadata::default()` to use `decimals: 18` as the safe fallback instead of `0`, matching the ERC-20 standard default.
2. Deprecate or gate the legacy path so it cannot be called for tokens whose actual decimals differ from 0.
3. Emit an on-chain event or revert when `decimals = 0` would be set for a token that has already received minted balances.
4. Provide a migration path for all existing legacy-deployed ERC-20 tokens to have their decimals corrected via `set_erc20_metadata`.

---

### Proof of Concept

1. Call `deploy_erc20_token` on Aurora with a borsh-encoded `AccountId` for a USDC-equivalent NEP-141 (6 decimals). The `deserialize` fallback maps this to `DeployErc20TokenArgs::Legacy`.
2. The ERC-20 is deployed with `_decimals = 0` (confirmed by `assert_eq!(metadata, Erc20Metadata::default())`).
3. Bridge 1,000,000 USDC units (= 1 USDC) via `ft_on_transfer`; the ERC-20 mints exactly 1,000,000 tokens to the recipient.
4. A lending protocol on Aurora calls `token.decimals()` → receives `0` → treats the 1,000,000 token balance as 1,000,000 whole USDC (worth ~$1,000,000).
5. Attacker deposits 1 USDC (1,000,000 units), borrows against $1,000,000 collateral value, drains the lending pool.

### Citations

**File:** engine/src/contract_methods/connector.rs (L123-126)
```rust
        match args {
            DeployErc20TokenArgs::Legacy(nep141) => {
                let address = engine::deploy_erc20_token(nep141, None, io, env, handler)?;

```

**File:** engine/src/contract_methods/connector.rs (L176-188)
```rust
        let erc20_metadata =
            if let Some(PromiseResult::Successful(bytes)) = handler.promise_result(0) {
                serde_json::from_slice::<FungibleTokenMetadata>(&bytes)
                    .map(|metadata| Erc20Metadata {
                        name: metadata.name,
                        symbol: metadata.symbol,
                        decimals: metadata.decimals,
                    })
                    .map_err(Into::<ParseArgsError>::into)?
            } else {
                return Err(errors::ERR_GETTING_ERC20_FROM_NEP141.into());
            };
        let address = engine::deploy_erc20_token(nep141, Some(erc20_metadata), io, env, handler)?;
```

**File:** engine/src/engine.rs (L1305-1313)
```rust
#[must_use]
pub fn setup_receive_erc20_tokens_input(recipient: &Address, amount: u128) -> Vec<u8> {
    let selector = ERC20_MINT_SELECTOR;
    let tail = ethabi::encode(&[
        ethabi::Token::Address(recipient.raw().0.into()),
        ethabi::Token::Uint(amount.into()),
    ]);

    [selector, tail.as_slice()].concat()
```

**File:** engine/src/engine.rs (L1327-1327)
```rust
    let erc20_metadata = erc20_metadata.unwrap_or_default();
```

**File:** engine/src/engine.rs (L1329-1334)
```rust
    let deploy_args = ethabi::encode(&[
        ethabi::Token::String(erc20_metadata.name),
        ethabi::Token::String(erc20_metadata.symbol),
        ethabi::Token::Uint(erc20_metadata.decimals.into()),
        ethabi::Token::Address(erc20_admin_address.raw().0.into()),
    ]);
```

**File:** engine/src/engine.rs (L2468-2475)
```rust
        let erc20_address = deploy_erc20_token(nep141, None, io, &env, &mut handler).unwrap();
        let metadata = engine
            .get_erc20_metadata(&Erc20Identifier::Erc20 {
                address: erc20_address,
            })
            .unwrap();

        assert_eq!(metadata, Erc20Metadata::default());
```

**File:** engine-types/src/parameters/connector.rs (L316-323)
```rust
impl Default for Erc20Metadata {
    fn default() -> Self {
        Self {
            name: "Empty".to_string(),
            symbol: "EMPTY".to_string(),
            decimals: 0,
        }
    }
```

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L21-28)
```text
    constructor (string memory metadata_name, string memory metadata_symbol, uint8 metadata_decimals, address admin)
        ERC20(metadata_name, metadata_symbol)
        AdminControlled(admin, 0)
    {
        _name = metadata_name;
        _symbol = metadata_symbol;
        _decimals = metadata_decimals;
    }
```

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L38-40)
```text
    function decimals() public view override returns (uint8) {
        return _decimals;
    }
```
