### Title
Missing Zero-Address Check in `AdminControlled` Constructor Renders Bridged ERC-20 Tokens Permanently Un-Mintable - (File: `etc/eth-contracts/contracts/AdminControlled.sol`)

### Summary
`AdminControlled.sol`, the base contract for all bridged ERC-20 tokens (`EvmErc20` and `EvmErc20V2`), sets `admin = _admin` in its constructor without any zero-address validation. The suppressed Slither warning (`// slither-disable-next-line missing-zero-check`) is explicit in-code acknowledgment of the missing guard. If `admin` is set to `address(0)` at construction time, the `mint` function — which the Aurora Engine calls to credit users when bridging NEP-141 tokens into Aurora — becomes permanently inaccessible, freezing all bridged funds.

### Finding Description

`AdminControlled.sol` constructor sets the admin without a zero-address check:

```solidity
constructor(address _admin, uint flags) {
    // slither-disable-next-line missing-zero-check
    admin = _admin;   // ← no require(_admin != address(0))
    paused = flags;
}
``` [1](#0-0) 

Both `EvmErc20` and `EvmErc20V2` inherit from `AdminControlled` and forward the `admin` constructor argument directly, also without any zero-address guard:

```solidity
constructor (... address admin)
    ERC20(metadata_name, metadata_symbol)
    AdminControlled(admin, 0)   // ← admin forwarded unchecked
``` [2](#0-1) [3](#0-2) 

The `admin` address passed at deployment is computed in `setup_deploy_erc20_input` as `current_address(current_account_id)`:

```rust
let erc20_admin_address = current_address(current_account_id);
// ...
ethabi::Token::Address(erc20_admin_address.raw().0.into()),
``` [4](#0-3) 

`current_address` is `near_account_to_evm_address(current_account_id.as_bytes())`. The `EngineState` stores `owner_id: AccountId` which defaults to an empty `AccountId` (the `Default` impl produces an empty string): [5](#0-4) 

And `AccountId::BorshDeserialize` explicitly allows an empty account ID for backward compatibility:

```rust
if account.is_empty() {
    return Ok(Self::default());
}
``` [6](#0-5) 

The `new` initializer in `admin.rs` converts `NewCallArgs` into `EngineState` without validating that `owner_id` is non-empty: [7](#0-6) 

If the engine is initialized with an empty `owner_id`, `current_account_id` resolves to the empty-string account, and `near_account_to_evm_address(b"")` produces a deterministic but potentially zero-equivalent EVM address. More directly, any deployment of `EvmErc20`/`EvmErc20V2` with `admin = address(0)` — whether by a deployment error or direct construction — is silently accepted.

### Impact Explanation

The `mint` function is gated by `onlyAdmin`:

```solidity
function mint(address account, uint256 amount) public onlyAdmin {
    _mint(account, amount);
}
``` [8](#0-7) 

The `onlyAdmin` modifier requires `msg.sender == admin`: [9](#0-8) 

The Aurora Engine calls `mint` (via `setup_receive_erc20_tokens_input`) every time a user bridges a NEP-141 token into Aurora: [10](#0-9) 

If `admin = address(0)`, no account can ever satisfy `msg.sender == address(0)` (the zero address cannot sign transactions). Every `mint` call reverts permanently. Users who bridge NEP-141 tokens have their NEAR-side tokens locked in the Aurora contract but receive no ERC-20 tokens on the EVM side — a **permanent fund freeze**.

### Likelihood Explanation

The `AdminControlled` constructor explicitly suppresses the Slither zero-address warning rather than fixing it. In the Aurora Engine's normal production flow, the admin is derived from the engine's NEAR account ID via `near_account_to_evm_address`, which is astronomically unlikely to be zero for a valid account. However:

1. The missing check is explicitly acknowledged in-code and not fixed.
2. A deployment error (e.g., passing `address(0)` when deploying `EvmErc20` directly) is silently accepted.
3. The `new` initializer accepts an empty `owner_id` without validation, which propagates to the EVM admin address computation.

The likelihood is **Low** (same classification as the external report), matching the external report's deployment-error scenario.

### Recommendation

- **Short term**: Add `require(_admin != address(0), "AdminControlled: admin is zero address")` in the `AdminControlled` constructor. Remove the `// slither-disable-next-line missing-zero-check` suppression.
- **Long term**: Add a validation in `setup_deploy_erc20_input` (or `deploy_erc20_token`) that asserts `erc20_admin_address != Address::zero()` before deploying the ERC-20 contract. Also validate that `owner_id` is non-empty in the `new` initializer.

### Proof of Concept

1. Deploy `EvmErc20` (or `EvmErc20V2`) with `admin = address(0)`:
   ```solidity
   EvmErc20 token = new EvmErc20("Token", "TKN", 18, address(0));
   // Constructor succeeds — no revert
   ```
2. Attempt to mint tokens (as the Aurora Engine would do when bridging):
   ```solidity
   token.mint(userAddress, 1000);
   // Reverts: msg.sender (engine address) != admin (address(0))
   ```
3. The token contract is permanently un-mintable. Any NEP-141 tokens bridged to this ERC-20 are locked on the NEAR side with no corresponding EVM tokens ever credited — permanent fund freeze. [1](#0-0) [2](#0-1) [11](#0-10)

### Citations

**File:** etc/eth-contracts/contracts/AdminControlled.sol (L10-16)
```text
    constructor(address _admin, uint flags) {
        // slither-disable-next-line missing-zero-check
        admin = _admin;

        // Add the possibility to set pause flags on the initialization
        paused = flags;
    }
```

**File:** etc/eth-contracts/contracts/AdminControlled.sol (L18-21)
```text
    modifier onlyAdmin {
        require(msg.sender == admin);
        _;
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

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L49-51)
```text
    function mint(address account, uint256 amount) public onlyAdmin {
        _mint(account, amount);
    }
```

**File:** etc/eth-contracts/contracts/EvmErc20V2.sol (L21-28)
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

**File:** engine/src/engine.rs (L1305-1314)
```rust
#[must_use]
pub fn setup_receive_erc20_tokens_input(recipient: &Address, amount: u128) -> Vec<u8> {
    let selector = ERC20_MINT_SELECTOR;
    let tail = ethabi::encode(&[
        ethabi::Token::Address(recipient.raw().0.into()),
        ethabi::Token::Uint(amount.into()),
    ]);

    [selector, tail.as_slice()].concat()
}
```

**File:** engine/src/engine.rs (L1317-1337)
```rust
pub fn setup_deploy_erc20_input(
    current_account_id: &AccountId,
    erc20_metadata: Option<Erc20Metadata>,
) -> Vec<u8> {
    #[cfg(feature = "error_refund")]
    let erc20_contract = include_bytes!("../../etc/eth-contracts/res/EvmErc20V2.bin");
    #[cfg(not(feature = "error_refund"))]
    let erc20_contract = include_bytes!("../../etc/eth-contracts/res/EvmErc20.bin");

    let erc20_admin_address = current_address(current_account_id);
    let erc20_metadata = erc20_metadata.unwrap_or_default();

    let deploy_args = ethabi::encode(&[
        ethabi::Token::String(erc20_metadata.name),
        ethabi::Token::String(erc20_metadata.symbol),
        ethabi::Token::Uint(erc20_metadata.decimals.into()),
        ethabi::Token::Address(erc20_admin_address.raw().0.into()),
    ]);

    [erc20_contract, deploy_args.as_slice()].concat()
}
```

**File:** engine/src/state.rs (L18-31)
```rust
#[derive(Default, Clone, PartialEq, Eq, Debug)]
pub struct EngineState {
    /// Chain id, according to the EIP-155 / ethereum-lists spec.
    pub chain_id: [u8; 32],
    /// Account which can upgrade this contract.
    /// Use empty to disable updatability.
    pub owner_id: AccountId,
    /// How many blocks after staging upgrade can deploy it.
    pub upgrade_delay_blocks: u64,
    /// Flag to pause and unpause the engine.
    pub is_paused: bool,
    /// Relayer key manager.
    pub key_manager: Option<AccountId>,
}
```

**File:** engine-types/src/account_id.rs (L93-96)
```rust
        // It's for saving backward compatibility.
        if account.is_empty() {
            return Ok(Self::default());
        }
```

**File:** engine/src/contract_methods/admin.rs (L55-88)
```rust
#[named]
pub fn new<I: IO + Copy, E: Env>(mut io: I, env: &E) -> Result<(), ContractError> {
    if state::get_state(&io).is_ok() {
        return Err(b"ERR_ALREADY_INITIALIZED".into());
    }

    let input = io.read_input().to_vec();
    let args = NewCallArgs::deserialize(&input).map_err(|_| errors::ERR_BORSH_DESERIALIZE)?;

    let initial_hashchain = args.initial_hashchain();
    let state: EngineState = args.into();

    if let Some(block_hashchain) = initial_hashchain {
        let block_height = env.block_height();
        let mut hashchain = Hashchain::new(
            state.chain_id,
            env.current_account_id(),
            block_height,
            block_hashchain,
        );

        hashchain.add_block_tx(
            block_height,
            function_name!(),
            &input,
            &[],
            &Bloom::default(),
        )?;
        crate::hashchain::save_hashchain(&mut io, &hashchain)?;
    }

    state::set_state(&mut io, &state)?;
    Ok(())
}
```
