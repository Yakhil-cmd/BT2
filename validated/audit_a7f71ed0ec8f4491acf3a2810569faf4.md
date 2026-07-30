[1](#0-0) [2](#0-1) [3](#0-2) [1](#0-0) [2](#0-1) [3](#0-2) 

### Title
Unconditional Ethereum Cursor Update Leads to Permanent Fund Loss - (`crates/sui-bridge/src/orchestrator.rs`)

### Summary
The `BridgeOrchestrator::run_eth_watcher` function updates the Ethereum event cursor to the end of a processed batch even if individual logs within that batch fail to be decoded or converted into bridge actions. This causes the orchestrator to permanently skip these events, as subsequent syncs start from the updated cursor. If a legitimate deposit event fails processing due to a parsing issue or conversion error, the funds remain locked in the Ethereum escrow contract and are never minted on Sui. [3](#0-2) 

### Finding Description
In `crates/sui-bridge/src/orchestrator.rs`, the `run_eth_watcher` task processes Ethereum logs in batches. The logic for handling conversion failures allows the cursor to advance past failed events:
1. When a log is not recognized as a bridge event, it is skipped with only a metric increment and an error log. [1](#0-0) 
2. When an event fails to convert to a `BridgeAction` via `try_into_bridge_action`, the error is logged, and the loop continues to the next log without persisting the action to the Write-Ahead Log (WAL). [2](#0-1) 
3. Crucially, `store.update_eth_event_cursor(contract, end_block)` is called at the end of the batch regardless of whether all logs were successfully processed. [3](#0-2) 

Because the cursor is advanced to `end_block`, any logs that were skipped will never be re-processed by the syncer, which starts scanning from the last stored cursor value upon restart or next poll.

### Impact Explanation
This vulnerability results in a permanent fund lock. A legitimate user deposit on Ethereum that triggers a log the bridge node fails to process (due to a bug in the Rust conversion logic or an unexpected but valid payload) will be permanently lost. The funds stay in the Ethereum bridge contract, but because the orchestrator advanced its cursor, it will never "see" that log again to retry the minting process on Sui. This constitutes a high-impact permanent fund lock for bridge users. [4](#0-3) 

### Likelihood Explanation
The likelihood is medium. It depends on the presence of edge cases in the event decoding logic in `crates/sui-bridge/src/abi.rs`. If any valid Ethereum transaction produces a log that the Rust `alloy` or internal bridge logic fails to parse, the unconditional cursor update ensures the failure is terminal and unrecoverable.

### Recommendation
The orchestrator should not advance the Ethereum cursor if any potentially relevant bridge event fails to be processed and persisted to the WAL. Instead, the task should either halt (requiring manual intervention or a fix) or implement a retry mechanism that prevents the cursor from moving past the failed log until it is successfully handled or explicitly marked as ignorable.

### Proof of Concept
1. A user initiates a deposit on Ethereum that results in a valid `EthTokenDeposited` log.
2. The `BridgeOrchestrator` receives this log in a batch ending at block `N`.
3. During processing, `bridge_event.try_into_bridge_action` returns an `Err` due to a parsing mismatch (e.g., an unexpected token address or malformed metadata that the Solidity contract allowed).
4. The orchestrator logs the error but does not add the action to the `actions` vector. [2](#0-1) 
5. The orchestrator calls `store.update_eth_event_cursor(contract, N)`. [3](#0-2) 
6. The deposit is now effectively forgotten by the bridge. Even after a node restart, the syncer will start from block `N`, skipping the failed deposit log entirely.
7. The user's funds remain in the Ethereum escrow, and no tokens are ever minted on Sui.

### Citations

**File:** crates/sui-bridge/src/orchestrator.rs (L198-203)
```rust
                if opt_bridge_event.is_none() {
                    // TODO: we probably should not miss any events, log for now.
                    metrics.eth_watcher_unrecognized_events.inc();
                    error!("Eth event not recognized: {:?}", log);
                    continue;
                }
```

**File:** crates/sui-bridge/src/orchestrator.rs (L223-226)
```rust
                    Err(e) => {
                        error!(eth_tx_hash=?log.tx_hash, eth_event_index=?log.log_index_in_tx, "Error converting EthBridgeEvent to BridgeAction: {:?}", e);
                    }
                }
```

**File:** crates/sui-bridge/src/orchestrator.rs (L234-236)
```rust
                store
                    .insert_pending_actions(&actions)
                    .expect("Store operation should not fail");
```

**File:** crates/sui-bridge/src/orchestrator.rs (L245-247)
```rust
            store
                .update_eth_event_cursor(contract, end_block)
                .expect("Store operation should not fail");
```
