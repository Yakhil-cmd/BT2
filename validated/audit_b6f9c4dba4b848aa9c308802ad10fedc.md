### Title
Silo Owner Can Race-Condition `erc20_fallback_address` to Steal Bridged ERC-20 Tokens - (`engine/src/engine.rs`)

### Summary

In Silo mode, the `erc20_fallback_address` and the Address whitelist are read from storage at the time `ft_on_transfer` executes, not at the time the user initiates the bridge transfer. A malicious silo owner can atomically remove a user's address from the whitelist and redirect `erc20_fallback_address` to an attacker-controlled address between the user's `ft_transfer_call` and the resulting `ft_on_transfer` callback, causing the user's bridged NEP-141 tokens to be minted to the attacker's EVM address instead of the user's.

### Finding Description

In `receive_erc20_tokens` (`engine/src/engine.rs`), the recipient address is determined at callback execution time by reading two owner-controlled storage values: the Address whitelist and `erc20_fallback_address`.

```rust
if let Some(fallback_address) = silo::get_erc20_fallback_address(&self.io)
    && !silo::is_allow_receive_erc20_tokens(&self.io, &recipient)
{
    recipient = fallback_address;
}
```

Both values are mutable by the silo owner at any time via `set_erc20_fallback_address()` and `remove_entry_from_whitelist()`, both of which are gated only by `require_owner_and_running`.

The cross-contract call flow for bridging NEP-141 tokens introduces a mandatory inter-block delay:
- **Block N**: User calls `ft_transfer_call` on the NEP-141 contract, specifying their EVM address in `msg`.
- **Block N or N+1**: The NEP-141 contract calls `ft_on_transfer` on Aurora Engine as a NEAR promise callback.

This gap gives the silo owner a window to submit two state-changing transactions before the callback executes:
1. `remove_entry_from_whitelist` — removes the user's EVM address from the Address whitelist.
2. `set_erc20_fallback_address` — sets the fallback address to an attacker-controlled EVM address.

When `ft_on_transfer` fires, `receive_erc20_tokens` reads the now-modified storage: the user's address fails the whitelist check, and the tokens are minted to the attacker's address.

The owner-controlled parameters involved:

- `erc20_fallback_address` is set via `set_erc20_fallback_address()` / `set_silo_params()`, both requiring `require_owner_and_running`. [1](#0-0) 
- The whitelist is modified via `remove_entry_from_whitelist`, also owner-only. [2](#0-1) 
- Both values are read live from storage at callback execution time. [3](#0-2) 

The `is_allow_receive_erc20_tokens` check reads the Address whitelist from storage at execution time with no snapshot or commitment from the user's original call. [4](#0-3) 

### Impact Explanation

**Critical — Direct theft of user funds.**

A user who initiates a NEP-141 → ERC-20 bridge transfer expects their tokens to be minted to the EVM address they specified in `msg`. If the silo owner executes the race condition, the tokens are instead minted to an attacker-controlled EVM address. The user's NEP-141 tokens are permanently lost from their perspective: the NEP-141 contract has already transferred them to Aurora Engine, and the ERC-20 mint goes to the wrong address. There is no refund path once `ft_on_transfer` returns `"0"` (success).

### Likelihood Explanation

**Medium.** The attack requires the silo owner to be malicious. In Silo mode, the owner is a third-party silo operator (not necessarily the Aurora protocol team), analogous to a market owner in the referenced report. The NEAR cross-contract call model guarantees at least one block of latency between `ft_transfer_call` and `ft_on_transfer`, making the race window reliable and not probabilistic. The owner does not need to front-run in a mempool sense — they simply need to submit their state-changing transactions before the callback receipt is processed, which is straightforward on NEAR.

### Recommendation

Commit the recipient address and whitelist status at the time the user initiates the transfer, not at callback execution time. One approach: pass the intended recipient and a snapshot of their whitelist status through the `ft_transfer_call` message and validate them against current state in `ft_on_transfer`, reverting (returning the full amount) if they have changed. Alternatively, add a time-lock or minimum delay to `set_erc20_fallback_address` and whitelist removal operations so that in-flight bridge transfers cannot be affected by parameter changes.

### Proof of Concept

1. Silo mode is active. `erc20_fallback_address` = `0xLEGIT`. User `alice` has EVM address `0xALICE` whitelisted.
2. Alice calls `ft_transfer_call` on the NEP-141 contract: `receiver_id = aurora`, `amount = 1000`, `msg = "0xALICE"`. This schedules a NEAR promise to call `ft_on_transfer` on Aurora.
3. Before the promise executes, the silo owner submits (in the same or next block):
   - `remove_entry_from_whitelist({ kind: Address, address: 0xALICE })`
   - `set_erc20_fallback_address({ address: Some(0xATTACKER) })`
4. The `ft_on_transfer` callback fires. `receive_erc20_tokens` is called. [5](#0-4) 
5. `recipient = 0xALICE`. `get_erc20_fallback_address` returns `0xATTACKER`. `is_allow_receive_erc20_tokens(0xALICE)` returns `false` (whitelist enabled, Alice removed). [3](#0-2) 
6. `recipient` is overwritten to `0xATTACKER`. 1000 ERC-20 tokens are minted to the attacker. Alice's tokens are stolen.

### Citations

**File:** engine/src/lib.rs (L805-815)
```rust
    #[unsafe(no_mangle)]
    pub extern "C" fn set_erc20_fallback_address() {
        let mut io = Runtime;
        let state = state::get_state(&io).sdk_unwrap();
        require_owner_and_running(&state, &io.predecessor_account_id())
            .map_err(ContractError::msg)
            .sdk_unwrap();

        let args: Erc20FallbackAddressArgs = io.read_input_borsh().sdk_unwrap();
        silo::set_erc20_fallback_address(&mut io, args.address);
    }
```

**File:** engine/src/contract_methods/silo/mod.rs (L91-95)
```rust
/// Remove an entry from a whitelist depending on a kind of list types in provided arguments.
pub fn remove_entry_from_whitelist<I: IO + Copy>(io: &I, args: &WhitelistArgs) {
    let (kind, entry) = get_kind_and_entry(args);
    Whitelist::init(io, kind).remove(entry);
}
```

**File:** engine/src/contract_methods/silo/mod.rs (L140-143)
```rust
/// Check if a user has the right to receive erc20 tokens.
pub fn is_allow_receive_erc20_tokens<I: IO + Copy>(io: &I, address: &Address) -> bool {
    is_address_allowed(io, address)
}
```

**File:** engine/src/engine.rs (L796-843)
```rust
    pub fn receive_erc20_tokens<P: PromiseHandler>(
        &mut self,
        token: &AccountId,
        args: &FtOnTransferArgs,
        current_account_id: &AccountId,
        handler: &mut P,
    ) -> Result<Option<SubmitResult>, ContractError> {
        let amount = args.amount.as_u128();
        // Parse message to determine recipient
        let mut recipient = {
            // The message should contain the recipient EOA address.
            let message = args.msg.strip_prefix("0x").unwrap_or(&args.msg);
            // Recipient - 40 characters (Address in hex without '0x' prefix)
            if message.len() < 40 {
                return Err(ParseOnTransferMessageError::WrongMessageFormat.into());
            }
            let mut address_bytes = [0; 20];
            hex::decode_to_slice(&message[..40], &mut address_bytes)
                .map_err(|_| ParseOnTransferMessageError::WrongMessageFormat)?;
            Address::from_array(address_bytes)
        };

        if let Some(fallback_address) = silo::get_erc20_fallback_address(&self.io)
            && !silo::is_allow_receive_erc20_tokens(&self.io, &recipient)
        {
            recipient = fallback_address;
        }

        let erc20_token = get_erc20_from_nep141(&self.io, token)?;
        let erc20_admin_address = current_address(current_account_id);
        let result = self
            .call(
                &erc20_admin_address,
                &erc20_token,
                Wei::zero(),
                setup_receive_erc20_tokens_input(&recipient, amount),
                u64::MAX,
                Vec::new(), // TODO: are there values we should put here?
                Vec::new(),
                handler,
            )
            .and_then(submit_result_or_err)?;

        sdk::log!("Mint {amount} ERC-20 tokens for: {}", recipient.encode());

        // Return SubmitResult so that it can be accessed in standalone engine.
        // This is used to help with the indexing of bridge transactions.
        Ok(Some(result))
```
