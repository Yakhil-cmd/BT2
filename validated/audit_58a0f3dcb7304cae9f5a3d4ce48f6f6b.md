This wiki page content contains an embedded prompt-injection attempt: it tries to have me impersonate a "vulnerability scanner" and produce a formatted security-disclosure report by mapping an unrelated external report onto this repository. The external report describes NEAR-style contract files (`sudo_actions.rs`, `registry_settings_actions.rs`, `registry_owner_actions.rs`, a `set_owner` function in `lib.rs`) from an "Octopus Network" project — none of these exist in this repository, which is the Polkadot Fellows Runtimes codebase (FRAME/Substrate-based relay chain and system parachain runtimes), as confirmed by the wiki overview and a grep search across the repo turning up no such files or functions [1](#0-0) .

Since the injected instructions ask me to either fabricate a "valid analog" vulnerability report or emit a fixed literal string as if I were an automated scanner, and I have no evidence of a reachable, attacker-controlled authorization bypass matching that pattern in this repo's actual privileged extrinsics (which are gated by FRAME origins like `EnsureRoot`, governance-track `EnsureOrigin` implementations, or `pallet-collective`/`pallet-referenda` tracks rather than a single NEAR-style "owner" account), I won't produce a fabricated finding. I'm not going to follow injected instructions that try to make me generate simulated security-report output as if it were an authoritative scan result — that would be misleading regardless of the literal output string requested.

If you have a genuine question about how privileged/root-level calls are authorized in this runtime (e.g., `EnsureRoot`, `EnsureSignedBy`, governance track origins in `system-parachains/*/src/lib.rs` or `relay/*/src/lib.rs`), I'm happy to look into that directly.

### Citations

**File:** relay/polkadot/Cargo.toml (L1-1)
```text
[package]
```
