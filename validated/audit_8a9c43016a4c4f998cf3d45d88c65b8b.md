Audit Report

## Title
Blocklist Bypass via Proxy Contract — `msg.sender` Emitted as `from_address` Allows Sanctioned Addresses to Receive ckETH/ckERC20 — (`rs/ethereum/cketh/minter/src/deposit.rs`, `rs/ethereum/cketh/minter/src/blocklist.rs`)

## Summary
Both Solidity deposit helpers emit `msg.sender` — the immediate caller — as the `from_address` field in their log events. A blocked address can deploy an unlisted proxy contract that calls the helper, causing the helper to emit the proxy's address instead of the blocked address. The Rust minter checks only the emitted `from_address` against the OFAC-derived blocklist, so `is_blocked(proxy)` returns `false` and ckETH/ckERC20 is minted to the sanctioned party's principal. This directly violates the stated invariant that ETH is not accepted from addresses on the blocklist.

## Finding Description
**Root cause — Solidity emits `msg.sender`, not `tx.origin`:**

`EthDepositHelper.sol` line 33 emits `msg.sender` as the sender field: [1](#0-0) 

`DepositHelperWithSubaccount.sol` lines 504 and 525–531 do the same for both ETH and ERC20 deposits: [2](#0-1) 

In Solidity, `msg.sender` is the immediate caller. If a proxy contract `P` calls `deposit()`, `msg.sender == address(P)`, regardless of who called `P`.

**Rust parser reads `from_address` verbatim from log topics:**

`ReceivedEthLogParser` reads topic index 1 as `from_address`: [3](#0-2) 

`ReceivedErc20LogParser` reads topic index 2: [4](#0-3) 

`ReceivedEthOrErc20LogParser` does the same: [5](#0-4) 

There is no secondary check against `tx.origin` or any other field. A grep across the entire `rs/ethereum/cketh/` tree confirms `tx.origin` is never referenced anywhere in the minter code. [6](#0-5) 

**Blocklist check operates only on the parsed `from_address`:**

`register_deposit_events` checks `is_blocked` solely on `event.from_address()`: [7](#0-6) 

`is_blocked` performs a binary search on `ETH_ADDRESS_BLOCKLIST`, which is derived from the OFAC SDN list: [8](#0-7) [9](#0-8) 

If the proxy address is not on the blocklist, the check passes and `process_event(s, event.into_deposit())` is called, triggering minting to the principal supplied by the blocked address.

## Impact Explanation
A sanctioned/blocked Ethereum address can receive minted ckETH or ckERC20 tokens on the Internet Computer by routing deposits through a freshly deployed, unlisted proxy contract. This directly violates the stated invariant: *"ETH is not accepted from nor sent to addresses on this list."* This constitutes a **significant ck-token security impact with concrete protocol harm** — specifically, sanctions compliance bypass enabling a blocked party to acquire chain-key assets — matching the **High ($2,000–$10,000)** bounty tier for significant Chain Fusion / ck-token security impact.

## Likelihood Explanation
The attack requires only: (1) deploying a proxy contract on Ethereum (permissionless, ~$5–$50 in gas), (2) transferring ETH or pre-approving ERC20 tokens to the proxy, and (3) calling `deposit()`/`depositErc20()` from the proxy. No privileged access, no key compromise, no governance majority is needed. Any blocked address can execute this immediately and repeatedly with different proxy addresses, making the blocklist trivially circumventable.

## Recommendation
The minter cannot retrieve `tx.origin` from log data because it is not emitted. The most robust fix is to modify both Solidity helpers to emit `tx.origin` alongside `msg.sender` and have the Rust minter check both fields against the blocklist, rejecting the deposit if either is blocked. This requires a coordinated upgrade of both the Solidity helper contracts and the Rust minter parser/event types. A less robust alternative is to document this as a known design limitation, but that would mean the compliance guarantee is weaker than the stated invariant.

## Proof of Concept
```solidity
// ProxyDeposit.sol — deployed by blocked address A
contract ProxyDeposit {
    CkEthDeposit helper = CkEthDeposit(HELPER_ADDRESS);

    function doDeposit(bytes32 principal) external payable {
        // msg.sender inside helper.deposit() == address(this), NOT address(A)
        helper.deposit{value: msg.value}(principal);
    }
}
```

Attack flow:
1. Blocked address `A` deploys `ProxyDeposit` → address `P` (not on blocklist).
2. `A` calls `P.doDeposit{value: 1 ether}(principal_of_A)`.
3. `P` calls `helper.deposit{value: 1 ether}(principal_of_A)`.
4. Helper emits `ReceivedEth(P, 1 ether, principal_of_A)`.
5. Minter scrapes log, parses `from_address = P`.
6. `is_blocked(P)` → `false`.
7. Minter mints 1 ckETH to `principal_of_A` — controlled by blocked address `A`.

The same pattern applies to ERC20 via `depositErc20` in `DepositHelperWithSubaccount.sol`. A local integration test can reproduce this by deploying a proxy against a local Anvil/Hardhat fork, calling through it, and verifying the minter's `register_deposit_events` path accepts the event.

### Citations

**File:** rs/ethereum/cketh/minter/EthDepositHelper.sol (L32-34)
```text
    function deposit(bytes32 _principal) public payable {
        emit ReceivedEth(msg.sender, msg.value, _principal);
        cketh_minter_main_address.transfer(msg.value);
```

**File:** rs/ethereum/cketh/minter/DepositHelperWithSubaccount.sol (L503-531)
```text
    function depositEth(bytes32 principal, bytes32 subaccount) public payable {
        emit ReceivedEthOrErc20(ZERO_ADDRESS, msg.sender, msg.value, principal, subaccount);
        minterAddress.transfer(msg.value);
    }

    /**
     * @dev Emits the `ReceivedEthOrErc20` event if the transfer succeeds.
     */
    function depositErc20(
        address erc20Address,
        uint256 amount,
        bytes32 principal,
        bytes32 subaccount
    ) public {
        require(erc20Address != ZERO_ADDRESS, "ERC20: depositErc20 from the zero address");
        IERC20 erc20Token = IERC20(erc20Address);
        erc20Token.safeTransferFrom(
            msg.sender,
            minterAddress,
            amount
        );

        emit ReceivedEthOrErc20(
            erc20Address,
            msg.sender,
            amount,
            principal,
            subaccount
        );
```

**File:** rs/ethereum/cketh/minter/src/eth_logs/parser.rs (L35-64)
```rust
        let (block_number, event_source) = ensure_not_pending(&entry)?;
        ensure_not_removed(&entry, event_source)?;

        ensure_topics(
            &entry,
            |topics| {
                topics.len() == 3 && topics.first() == Some(&Hex32::from(RECEIVED_ETH_EVENT_TOPIC))
            },
            event_source,
        )?;
        let from_address = parse_address(&entry.topics[1], event_source)?;
        let principal = parse_principal(&entry.topics[2], event_source)?;

        let [value_bytes] = parse_hex_into_32_byte_words(entry.data, event_source)?;
        let EventSource {
            transaction_hash,
            log_index,
        } = event_source;

        Ok(ReceivedEthEvent {
            transaction_hash,
            block_number,
            log_index,
            from_address,
            value: Wei::from_be_bytes(value_bytes),
            principal,
            subaccount: None,
        }
        .into())
    }
```

**File:** rs/ethereum/cketh/minter/src/eth_logs/parser.rs (L83-84)
```rust
        let from_address = parse_address(&entry.topics[2], event_source)?;
        let principal = parse_principal(&entry.topics[3], event_source)?;
```

**File:** rs/ethereum/cketh/minter/src/eth_logs/parser.rs (L124-126)
```rust
        let erc20_contract_address = parse_address(&entry.topics[1], event_source)?;
        let from_address = parse_address(&entry.topics[2], event_source)?;
        let principal = parse_principal(&entry.topics[3], event_source)?;
```

**File:** rs/ethereum/cketh/minter/src/deposit.rs (L323-341)
```rust
        if crate::blocklist::is_blocked(&event.from_address()) {
            log!(
                INFO,
                "Received event from a blocked address: {} for {} {scraping_id}",
                event.from_address(),
                event.value(),
            );
            mutate_state(|s| {
                process_event(
                    s,
                    EventType::InvalidDeposit {
                        event_source: event.source(),
                        reason: format!("blocked address {}", event.from_address()),
                    },
                )
            });
        } else {
            mutate_state(|s| process_event(s, event.into_deposit()));
        }
```

**File:** rs/ethereum/cketh/minter/src/blocklist.rs (L15-17)
```rust
/// ETH is not accepted from nor sent to addresses on this list.
/// NOTE: Keep it sorted!
const ETH_ADDRESS_BLOCKLIST: &[Address] = &[
```

**File:** rs/ethereum/cketh/minter/src/blocklist.rs (L107-109)
```rust
pub fn is_blocked(address: &Address) -> bool {
    ETH_ADDRESS_BLOCKLIST.binary_search(address).is_ok()
}
```
