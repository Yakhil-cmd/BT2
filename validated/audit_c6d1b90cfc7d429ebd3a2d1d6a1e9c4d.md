## Analysis

The core of the Sherlock report is: a contract dispatches on the **first bytes of raw call data** to decide between "compact/special encoding" and "normal ABI call", but reserves no dedicated prefix for the special path, so ordinary call data can collide with the special encoding and be misinterpreted, causing unintended state changes.

nearcore's `near-wallet-contract` implements essentially the identical dispatch pattern. `parse_tx_data` in `internal.rs` inspects only the first 4 bytes of an RLP-decoded Ethereum transaction's `data` field and, if they match one of four hard-coded 4-byte constants, decodes the remainder as a privileged Near action (`FunctionCall`, `Transfer`, `AddKey`, `DeleteKey`) instead of falling through to ERC-20 emulation / plain base-token transfer: [1](#0-0) [2](#0-1) 

These selectors are ordinary 4-byte `keccak256`-derived ABI selectors — not out-of-band, reserved values — exactly the flaw described in the Woo report: [3](#0-2) 

If the `ADD_KEY_SELECTOR` branch matches and the remaining bytes decode successfully as the `AddKeyAction` ABI signature, the parsed action grants a `FunctionCall`-permission access key with an attacker-chosen public key, allowance, receiver, and method names on the wallet's own account: [4](#0-3) 

Only full-access-key grants are explicitly blocked; limited `FunctionCall` access keys are not: [5](#0-4) 

This matches the "access-key authorization" category explicitly listed as an acceptable analog target.

### Title
Wallet-Contract dispatches privileged Near actions (AddKey/FunctionCall/Transfer/DeleteKey) from unreserved 4-byte ABI selectors in raw Ethereum calldata - (File: `runtime/near-wallet-contract/implementation/wallet-contract/src/internal.rs`)

### Summary
`WalletContract::rlp_execute` accepts an RLP-encoded, user-signed Ethereum-style transaction and decides how to interpret its `data` field purely by matching the first 4 bytes against a small set of hard-coded, unreserved constants (`FUNCTION_CALL_SELECTOR`, `TRANSFER_SELECTOR`, `ADD_KEY_SELECTOR`, `DELETE_KEY_SELECTOR`). If the raw call data a user signs (e.g. for what they believe is an ordinary ERC-20-style call or a generic contract interaction) happens to begin with one of these constants and the remaining bytes ABI-decode successfully according to the matching signature, the wallet silently reinterprets the transaction as a completely different, privileged Near action instead of the intended emulated call/transfer.

### Finding Description
`parse_tx_data` (`internal.rs:234-310`) performs `match &tx.data[0..4]` against `FUNCTION_CALL_SELECTOR`, `TRANSFER_SELECTOR`, `ADD_KEY_SELECTOR`, `DELETE_KEY_SELECTOR` before ever considering the ERC-20 emulation path (`eth_emulation::try_emulation`, matched only in the `_ =>` fallback arm). None of these four bytes are reserved out-of-band the way, for example, the `MessageDiscriminant` scheme in `signable_message.rs` reserves 30/31-bit ranges specifically to avoid this class of confusion between transaction types: [6](#0-5) 

Because the wallet-contract selectors are ordinary ABI-style 4-byte hashes rather than a reserved sentinel, any raw calldata that a user is induced to sign (via a phishing dApp, a malicious "approve"/"call" prompt, or any workflow producing arbitrary ABI-shaped bytes) that happens to start with `ADD_KEY_SELECTOR` (`0x753ce5ab`) and ABI-decodes as the `ADD_KEY_SIGNATURE` tuple will be executed as an `AddKeyAction` granting a `FunctionCall`-permission access key with attacker-chosen `public_key`, `allowance`, `receiver_id`, and `method_names` on the victim's own wallet-contract account — regardless of what the signer believed they were authorizing.

### Impact Explanation
A successful collision results in an unauthorized `AddKey` action executing on the victim's wallet account with attacker-controlled parameters: [5](#0-4) 

This is a concrete unauthorized access-key authorization: the attacker obtains a limited `FunctionCall` access key (bounded by an allowance) on the victim's account without the victim knowingly consenting to that specific grant, enabling gas-scoped unauthorized calls/spends from the victim's wallet contract. The same mechanism (with `TRANSFER_SELECTOR`/`FUNCTION_CALL_SELECTOR`) can also redirect funds or trigger unintended cross-contract calls with attacker-chosen `receiver_id`/`method_name`/`args`/`deposit`, since the target/relayer validation in `validate_tx_relayer_data` only checks the `to` address/self-consistency, not that the encoded action matches user intent.

### Likelihood Explanation
As in the original report, the likelihood is low but non-negligible and matches the original bug class exactly: the selectors are ordinary fixed 4-byte constants that are public (compiled into the open-source contract), so an adversary does not need to search for a probabilistic collision — they only need to construct or induce signing of calldata beginning with the known bytes for a chosen action (e.g. `ADD_KEY_SELECTOR`) whose remainder they fully control and which passes ABI decoding. This is analogous to (and easier to intentionally trigger than) the accidental function-selector collisions described in the Sherlock report, since here the "special" encoding itself uses public, non-reserved, easily-reproducible byte sequences.

### Recommendation
Reserve an explicit, out-of-band discriminator (e.g. a fixed magic byte sequence not derivable from any plausible ABI call, or a length/format check that cannot coincide with legitimate ABI-encoded calldata) to distinguish "Near-native action" encodings from ordinary Ethereum ABI calldata in `parse_tx_data`, rather than relying on 4-byte selector matching alone. Apply the same reserved-discriminant discipline already used for `MessageDiscriminant` (`signable_message.rs`) to the wallet-contract's action dispatch path, and/or require an additional binding commitment (e.g. explicit user confirmation of the decoded action type) before executing `AddKey`/`FunctionCall`/`Transfer` actions parsed from otherwise-arbitrary transaction payloads.

### Proof of Concept
1. Attacker crafts (or induces the victim's wallet/dApp tooling to produce) an RLP Ethereum transaction with `to` = the victim's own eth-implicit account address (satisfying `validate_tx_relayer_data`'s self-target check) and `data` = `ADD_KEY_SELECTOR (0x753ce5ab)` followed by ABI-encoded `(public_key_kind, public_key, nonce, is_full_access=false, is_limited_allowance, allowance, receiver_id, method_names)` matching `ADD_KEY_SIGNATURE`, where `public_key` is attacker-controlled.
2. Victim signs the transaction believing it to be an innocuous self-transfer or contract call (the UI/relayer tooling does not decode/display the Near-native-action interpretation).
3. Relayer submits it via `rlp_execute`; `parse_tx_data` matches `ADD_KEY_SELECTOR`, ABI-decodes successfully, and yields `Action::AddKey { ... }`.
4. `action_to_promise` executes `Promise::new(target).add_access_key_allowance_with_nonce(attacker_public_key, allowance, receiver_id, method_names, nonce)`, granting the attacker a `FunctionCall`-permission access key on the victim's wallet-contract account.

### Citations

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/internal.rs (L234-243)
```rust
fn parse_tx_data(
    target: &AccountId,
    tx: &NormalizedEthTransaction,
    fee: NearToken,
    context: &ExecutionContext,
) -> Result<(Action, ParsableTransactionKind), Error> {
    if tx.data.len() < 4 {
        return Err(Error::User(UserError::InvalidAbiEncodedData));
    }
    match &tx.data[0..4] {
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/internal.rs (L272-309)
```rust
        ADD_KEY_SELECTOR => {
            let (
                public_key_kind,
                public_key,
                nonce,
                is_full_access,
                is_limited_allowance,
                allowance,
                receiver_id,
                method_names,
            ) = ethabi_utils::abi_decode(&ADD_KEY_SIGNATURE, &tx.data[4..])?;
            Ok((
                Action::AddKey {
                    public_key_kind,
                    public_key,
                    nonce,
                    is_full_access,
                    is_limited_allowance,
                    allowance,
                    receiver_id,
                    method_names,
                },
                ParsableTransactionKind::SelfNearNativeAction,
            ))
        }
        DELETE_KEY_SELECTOR => {
            let (public_key_kind, public_key) =
                ethabi_utils::abi_decode(&DELETE_KEY_SIGNATURE, &tx.data[4..])?;
            Ok((
                Action::DeleteKey { public_key_kind, public_key },
                ParsableTransactionKind::SelfNearNativeAction,
            ))
        }
        _ => {
            let (action, emulation_kind) = eth_emulation::try_emulation(target, tx, fee, context)?;
            Ok((action, ParsableTransactionKind::EthEmulation(emulation_kind)))
        }
    }
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/types.rs (L13-47)
```rust
pub const FUNCTION_CALL_SELECTOR: &[u8] = &[0x61, 0x79, 0xb7, 0x07];
pub const FUNCTION_CALL_SIGNATURE: [ParamType; 5] = [
    ParamType::String,   // receiver_id
    ParamType::String,   // method_name
    ParamType::Bytes,    // args
    ParamType::Uint(64), // gas
    ParamType::Uint(32), // yocto_near
];

pub const TRANSFER_SELECTOR: &[u8] = &[0x3e, 0xd6, 0x41, 0x24];
pub const TRANSFER_SIGNATURE: [ParamType; 2] = [
    ParamType::String,   // receiver_id
    ParamType::Uint(32), // yocto_near
];

pub const ADD_KEY_SELECTOR: &[u8] = &[0x75, 0x3c, 0xe5, 0xab];
// This one needs to be `LazyLock` because it requires `Box` (non-const) in the `Array`.
pub static ADD_KEY_SIGNATURE: LazyLock<[ParamType; 8]> = LazyLock::new(|| {
    [
        ParamType::Uint(8),                            // public_key_kind
        ParamType::Bytes,                              // public_key
        ParamType::Uint(64),                           // nonce
        ParamType::Bool,                               // is_full_access
        ParamType::Bool,                               // is_limited_allowance
        ParamType::Uint(128),                          // allowance
        ParamType::String,                             // receiver_id
        ParamType::Array(Box::new(ParamType::String)), // method_names
    ]
});

pub const DELETE_KEY_SELECTOR: &[u8] = &[0x3f, 0xc6, 0xd4, 0x04];
pub const DELETE_KEY_SIGNATURE: [ParamType; 2] = [
    ParamType::Uint(8), // public_key_kind
    ParamType::Bytes,   // public_key
];
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L475-496)
```rust
fn action_to_promise(target: AccountId, action: near_action::Action) -> Result<Promise, Error> {
    match action {
        near_action::Action::FunctionCall(action) => Ok(Promise::new(target).function_call(
            action.method_name,
            action.args,
            action.deposit,
            action.gas,
        )),
        near_action::Action::Transfer(action) => Ok(Promise::new(target).transfer(action.deposit)),
        near_action::Action::AddKey(action) => match action.access_key.permission {
            near_action::AccessKeyPermission::FullAccess => {
                Err(Error::User(UserError::UnsupportedAction(UnsupportedAction::AddFullAccessKey)))
            }
            near_action::AccessKeyPermission::FunctionCall(access) => Ok(Promise::new(target)
                .add_access_key_allowance_with_nonce(
                    action.public_key,
                    access.allowance.and_then(Allowance::limited).unwrap_or(Allowance::Unlimited),
                    access.receiver_id,
                    access.method_names.join(","),
                    action.access_key.nonce,
                )),
        },
```

**File:** core/primitives/src/signable_message.rs (L17-21)
```rust
// TODO: consider making these public once there is an approved standard.
const MIN_ON_CHAIN_DISCRIMINANT: u32 = 1 << 30;
const MAX_ON_CHAIN_DISCRIMINANT: u32 = (1 << 31) - 1;
const MIN_OFF_CHAIN_DISCRIMINANT: u32 = 1 << 31;
const MAX_OFF_CHAIN_DISCRIMINANT: u32 = u32::MAX;
```
