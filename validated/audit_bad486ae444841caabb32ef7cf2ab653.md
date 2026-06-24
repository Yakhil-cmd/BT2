All code references are confirmed. Every step in the call chain is verified against the actual source. Let me write the report.

---

Audit Report

## Title
Single `NetworkMessage::Unknown` Permanently Removes Peer Address, Enabling Address Book Depletion — (`rs/bitcoin/adapter/src/connectionmanager.rs`)

## Summary

`process_unknown_message` unconditionally calls `internal_discard` on any peer that sends a single unknown Bitcoin P2P message, with no rate limiting, counter, or grace period. This triggers permanent removal of that peer's address from the address book when DNS seeds are configured (the normal production deployment). An attacker controlling enough Bitcoin-protocol-speaking nodes can deplete the adapter's address book and force continuous re-discovery from DNS seeds, disrupting the IC's Bitcoin integration (ckBTC, canister Bitcoin API calls) for as long as the attack is sustained.

## Finding Description

The full call chain is confirmed in production code:

**Step 1 — Router dispatch:** The router's main event loop passes every received `NetworkMessage::Unknown` to `connection_manager.process_bitcoin_network_message`. [1](#0-0) 

**Step 2 — Match arm:** `process_bitcoin_network_message` matches `NetworkMessage::Unknown` and calls `process_unknown_message`. [2](#0-1) 

**Step 3 — Unconditional discard:** `process_unknown_message` logs the message and immediately calls `internal_discard`. There is no misbehavior counter, no threshold, no connection-state guard, and no grace period. The function returns `Ok(())`, so the router's outer `discard` guard at L96-99 does not fire a second time. [3](#0-2) 

**Step 4 — State transition:** `internal_discard` calls `conn.discard()`, which sets the connection state to `AdapterDiscarded` and aborts the stream task. [4](#0-3) [5](#0-4) 

**Step 5 — Reap on next tick:** `reap_disconnected`, called from `manage_connections` on every 100 ms tick, matches `AdapterDiscarded` and calls `address_book.discard()`. [6](#0-5) 

**Step 6 — Permanent removal:** `address_book.discard()` removes the address from both `active_addresses` and `known_addresses` when `has_seeds()` is true. `has_seeds()` returns `true` whenever `dns_seeds` is non-empty, which is always the case in production. [7](#0-6) [8](#0-7) 

No connection-state check gates `process_unknown_message`; it fires for connections in any `ConnectionState`, including before the handshake is complete.

When the address book is depleted, `make_connection` falls back to `resolve_next_seed()`, which rebuilds from DNS seeds. The adapter is not permanently bricked, but the attacker can sustain the attack by continuously getting new addresses into the book (via normal `addr` message propagation) and then sending `Unknown` from each, keeping the adapter in a perpetual re-discovery loop. [9](#0-8) 

## Impact Explanation

During the re-discovery phase the adapter cannot serve Bitcoin data to the IC. All ckBTC operations and canister Bitcoin API calls that depend on the adapter stall for as long as the attacker sustains the campaign. This is a sustained, application/platform-level DoS against a core Chain Fusion financial integration, matching the **High ($2,000–$10,000)** impact class: "Application/platform-level DoS … or subnet availability impact not based on raw volumetric DDoS" and "Significant Chain Fusion, ck-token … security impact with concrete user or protocol harm."

## Likelihood Explanation

Running Bitcoin-protocol-speaking nodes is unprivileged and low-cost. The attacker:
1. Spins up nodes that complete the Bitcoin P2P handshake correctly.
2. Waits for their addresses to propagate into the adapter's address book via `addr` messages from other peers, or directly sends `addr` messages from a node the adapter already connects to.
3. When the adapter connects outbound to an attacker node, the attacker immediately sends a message with an unknown command string.
4. Repeats across all addresses they have seeded into the book.

No admin access, key material, governance majority, BGP/DNS hijack, or victim mistake is required. The attack is repeatable and can be sustained indefinitely.

## Recommendation

- Add a per-address misbehavior counter. Only call `internal_discard` after N unknown messages within a time window, not on the first occurrence.
- Alternatively, treat `Unknown` as a soft disconnect: call `conn.disconnect()` instead of `conn.discard()`, which transitions to `NodeDisconnected` and causes `reap_disconnected` to call `remove_from_active` (returning the address to `known_addresses`) rather than permanently discarding it.
- Add a minimum address book floor: if `known_addresses` would drop below `min_addresses`, demote to `NodeDisconnected` instead of permanently discarding.

## Proof of Concept

State-machine test (no network required):

1. Create a `ConnectionManager` with DNS seeds configured (so `has_seeds()` returns `true`).
2. Manually insert 10 `Connection` objects with `AddressEntry::Discovered` in `HandshakeComplete` state into `manager.connections`, and insert their addresses into `address_book.active_addresses`.
3. For each of the 10 addresses, call `manager.process_bitcoin_network_message(addr_i, &NetworkMessage::Unknown { command: "exploit".parse().unwrap(), payload: vec![] })`.
4. Call `manager.reap_disconnected()`.
5. Assert `manager.address_book.size() == 0` — all addresses have been permanently removed from both `active_addresses` and `known_addresses`.

The existing test infrastructure in `connectionmanager.rs` (e.g., `Connection::new_with_state`, direct `manager.connections.insert`) already provides all the scaffolding needed to write this as a `#[test]` without any network I/O. [10](#0-9)

### Citations

**File:** rs/bitcoin/adapter/src/router.rs (L96-99)
```rust
                    if let Err(ProcessNetworkMessageError::InvalidMessage) =
                        connection_manager.process_bitcoin_network_message(address, &message) {
                        connection_manager.discard(&address);
                    }
```

**File:** rs/bitcoin/adapter/src/connectionmanager.rs (L157-161)
```rust
    fn internal_discard(&mut self, address: &SocketAddr) {
        if let Ok(conn) = self.get_connection(address) {
            conn.discard();
        }
    }
```

**File:** rs/bitcoin/adapter/src/connectionmanager.rs (L279-295)
```rust
    fn reap_disconnected(&mut self) {
        let mut disconnects = vec![];
        for (addr, conn) in self.connections.iter() {
            match conn.state() {
                ConnectionState::AdapterDiscarded => {
                    self.address_book.discard(conn.address_entry());
                }
                ConnectionState::NodeDisconnected => {
                    self.address_book.remove_from_active(conn.address_entry());
                }
                _ => {}
            }

            if conn.is_disconnected() {
                disconnects.push(*addr);
            }
        }
```

**File:** rs/bitcoin/adapter/src/connectionmanager.rs (L308-313)
```rust
        let address_entry_result = if !self.address_book.has_enough_addresses() {
            self.address_book.resolve_next_seed().await
        } else {
            self.address_book.pop()
        };
        let address_entry = address_entry_result.map_err(ConnectionManagerError::AddressBook)?;
```

**File:** rs/bitcoin/adapter/src/connectionmanager.rs (L577-594)
```rust
    fn process_unknown_message(
        &mut self,
        address: &SocketAddr,
        command: &CommandString,
        payload: &[u8],
    ) -> Result<(), ProcessNetworkMessageError> {
        // If we receive an unknown message from a BTC node, the adapter should log
        // the message for further analysis.
        warn!(
            self.logger,
            "Received an unknown message from {}, command: {}, payload: {}",
            address,
            command,
            hex::encode(payload),
        );
        self.internal_discard(address);
        Ok(())
    }
```

**File:** rs/bitcoin/adapter/src/connectionmanager.rs (L695-697)
```rust
            NetworkMessage::Unknown { command, payload } => {
                self.process_unknown_message(&address, command, payload)
            }
```

**File:** rs/bitcoin/adapter/src/connectionmanager.rs (L713-722)
```rust
#[cfg(test)]
mod test {
    use super::*;
    use crate::config::test::ConfigBuilder;
    use bitcoin::p2p::ServiceFlags;
    use bitcoin::{Block, Network, block::Header};
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use std::str::FromStr;

```

**File:** rs/bitcoin/adapter/src/connection.rs (L197-200)
```rust
    pub fn discard(&mut self) {
        self.state = ConnectionState::AdapterDiscarded;
        self.handle.abort();
    }
```

**File:** rs/bitcoin/adapter/src/addressbook.rs (L267-269)
```rust
    pub fn has_seeds(&self) -> bool {
        !self.dns_seeds.is_empty()
    }
```

**File:** rs/bitcoin/adapter/src/addressbook.rs (L292-301)
```rust
    pub fn discard(&mut self, address: &AddressEntry) {
        if let AddressEntry::Discovered(addr) = address {
            if self.has_seeds() {
                self.active_addresses.remove(addr);
                self.known_addresses.remove(addr);
            } else {
                self.remove_from_active(address);
            }
        }
    }
```
