### Title
Hash-collision in Axelar bridge approval hashing allows call-origin forgery via `abi.encodePacked`-style concatenation - (File: `crates/sui-axelar-cgp/move/sources/validators.move`)

### Summary
`AxelarValidators::add_approval` and `AxelarValidators::take_approved_call` build the value that gets hashed and checked for authenticity by directly concatenating raw bytes of two variable-length `String` fields (`source_chain`, `source_address`) with `vector::append`, with no length prefix or delimiter between them. This is the exact Move analogue of Solidity's `abi.encodePacked(a, b)` collision bug referenced in the external report: when two or more dynamic-length values are packed together without a length separator, different `(source_chain, source_address)` pairs can serialize to the identical byte string and therefore hash to the identical `approval_hash`.

### Finding Description
`add_approval` computes and stores the "authenticity" hash for a cross-chain call approval: [1](#0-0) 

```
let mut data = vector[];
vector::append(&mut data, address::to_bytes(cmd_id));
vector::append(&mut data, address::to_bytes(target_id));
vector::append(&mut data, *string::as_bytes(&source_chain));
vector::append(&mut data, *string::as_bytes(&source_address));
vector::append(&mut data, payload_hash);

table::add(&mut axelar.approvals, cmd_id, Approval {
    approval_hash: hash::keccak256(&data),
});
```

`take_approved_call` later reconstructs the same byte layout from caller-supplied `source_chain`/`source_address` arguments and checks it against the stored `approval_hash`: [2](#0-1) 

`cmd_id`, `target_id`, and `payload_hash` are fixed-length (32-byte) values, but `source_chain` and `source_address` are both unbounded, dynamic-length `String`s and are placed directly adjacent in the byte stream with no length-prefix separating them. Because `vector::append(*string::as_bytes(...))` has no equivalent to BCS's length-prefixed vector encoding, this is precisely the packed/collidable pattern described in the report (`keccak256(abi.encodePacked(a, b))` where `a`/`b` are dynamic). For example, `source_chain = "AB"`, `source_address = "C"` produces the exact same `data` bytes (and therefore the exact same `keccak256` hash) as `source_chain = "A"`, `source_address = "BC"`.

This differs from the properly-guarded Sui-native bridge implementation in `crates/sui-framework/packages/bridge/sources/message.move`, where every variable-length field is preceded by an explicit `u8` length prefix before appending its bytes: [3](#0-2) 

and in the Rust bridge encoding (`crates/sui-bridge/src/encoding.rs`), where every dynamic field is likewise length-prefixed. The Axelar CGP module lacks this protection.

### Impact Explanation
`source_chain` and `source_address` are the fields a downstream `Channel`/dApp module relies on to authenticate the true origin of a cross-chain call (this is the entire point of the Axelar Cross-Chain Gateway Protocol — target contracts gate privileged actions, such as minting wrapped tokens or executing governance actions, based on which `source_chain`/`source_address` sent the approved call). Because the hash used to gate `take_approved_call` can collide across different `(source_chain, source_address)` pairs, an attacker who knows (or can influence) one legitimately-validator-signed approval for a given `cmd_id` can call `take_approved_call` while supplying a *different* `source_chain`/`source_address` combination that produces the same `approval_hash`, causing the `Channel` to believe the call originated from an address/chain that never actually signed off on it. If a receiving dApp on Sui trusts `source_address` to authorize minting or unlocking funds (the typical bridge pattern), this collision constitutes bridge message forgery that can enable illegitimate mint/unlock — a Critical-class outcome per the allowed-impact list.

### Likelihood Explanation
Exploitation requires no privileged access: any unauthenticated caller can invoke `take_approved_call` (via `axelar::gateway::take_approved_call`) with attacker-chosen `source_chain`/`source_address` strings, as long as they can construct a colliding pair for a `cmd_id` that has a pending `Approval`. Constructing a byte-level collision between two ASCII strings concatenated back-to-back is trivial (move characters across the boundary between the two strings). The main constraint on exploitability is the specific interpretation a downstream `Channel`/application places on `source_address`/`source_chain` — the vulnerability is a hash-collision-enabling primitive in the bridge/gateway library itself, and its severity depends on the receiving application's trust in those fields, which is the norm for token-bridge/messaging use of Axelar GMP.

Note on scope: this code lives in `crates/sui-axelar-cgp`, a Move integration of the third-party Axelar Cross-Chain Gateway Protocol shipped in the Sui repository, distinct from Sui's own native bridge (`crates/sui-bridge`, `crates/sui-framework/packages/bridge`), which I confirmed correctly length-prefixes all dynamic fields and is not vulnerable to this collision. Whether this module is considered in-scope "bridge code" for the Sui Protocol bounty program is uncertain, since it is a reference/example integration rather than validator-critical infrastructure; I am flagging this uncertainty rather than asserting definitive bounty eligibility.

### Recommendation
Length-prefix every dynamic-length field before concatenation, exactly as the official Sui bridge modules already do, e.g.:
```
vector::append(&mut data, address::to_bytes(cmd_id));
vector::append(&mut data, address::to_bytes(target_id));
data.push_back((vector::length(string::as_bytes(&source_chain)) as u8));
vector::append(&mut data, *string::as_bytes(&source_chain));
data.push_back((vector::length(string::as_bytes(&source_address)) as u8));
vector::append(&mut data, *string::as_bytes(&source_address));
vector::append(&mut data, payload_hash);
```
Alternatively, switch to BCS serialization of a structured tuple/struct (which inherently includes length prefixes for vectors/strings) instead of manual `vector::append` concatenation, in both `add_approval` and `take_approved_call`.

### Proof of Concept
1. Axelar validators sign and relay an approval for `cmd_id = X`, `source_chain = "A"`, `source_address = "BC"`, `target_id = T`, `payload_hash = H`. `add_approval` stores:
   `approval_hash = keccak256(X || T || "A" || "BC" || H)`.
2. An attacker calls `axelar::gateway::take_approved_call(axelar, X, "AB", "C", T, payload)` where `keccak256(payload) == H`. The reconstructed `data` is:
   `X || T || "AB" || "C" || H`
   which is byte-for-byte identical to the originally signed data (`"A" || "BC"` vs `"AB" || "C"` concatenate to the same 3-byte string `"ABC"`), so `hash::keccak256(&data) == approval_hash` passes.
3. `channel::create_approved_call` is created with the attacker-supplied `source_chain = "AB"`, `source_address = "C"` instead of the validator-approved `"A"`/`"BC"`, and is delivered to the target `Channel`, which will authorize logic based on the forged origin fields. [4](#0-3)

### Citations

**File:** crates/sui-axelar-cgp/move/sources/validators.move (L168-186)
```text
    public(package) fun add_approval(
        axelar: &mut AxelarValidators,
        cmd_id: address,
        source_chain: String,
        source_address: String,
        target_id: address,
        payload_hash: vector<u8>
    ) {
        let mut data = vector[];
        vector::append(&mut data, address::to_bytes(cmd_id));
        vector::append(&mut data, address::to_bytes(target_id));
        vector::append(&mut data, *string::as_bytes(&source_chain));
        vector::append(&mut data, *string::as_bytes(&source_address));
        vector::append(&mut data, payload_hash);

        table::add(&mut axelar.approvals, cmd_id, Approval {
            approval_hash: hash::keccak256(&data),
        });
    }
```

**File:** crates/sui-axelar-cgp/move/sources/validators.move (L193-222)
```text
    public(package) fun take_approved_call(
        axelar: &mut AxelarValidators,
        cmd_id: address,
        source_chain: String,
        source_address: String,
        target_id: address,
        payload: vector<u8>
    ): ApprovedCall {
        let Approval {
            approval_hash,
        } = table::remove(&mut axelar.approvals, cmd_id);

        let mut data = vector[];
        vector::append(&mut data, address::to_bytes(cmd_id));
        vector::append(&mut data, address::to_bytes(target_id));
        vector::append(&mut data, *string::as_bytes(&source_chain));
        vector::append(&mut data, *string::as_bytes(&source_address));
        vector::append(&mut data, hash::keccak256(&payload));

        assert!(hash::keccak256(&data) == approval_hash, EPayloadHashMismatch);

        // Friend only.
        channel::create_approved_call(
            cmd_id,
            source_chain,
            source_address,
            target_id,
            payload,
        )
    }
```

**File:** crates/sui-framework/packages/bridge/sources/message.move (L299-311)
```text
    let mut payload = vector[];

    // sender address should be less than 255 bytes so can fit into u8
    payload.push_back((vector::length(&sender_address) as u8));
    payload.append(sender_address);
    payload.push_back(target_chain);
    // target address should be less than 255 bytes so can fit into u8
    payload.push_back((vector::length(&target_address) as u8));
    payload.append(target_address);
    payload.push_back(token_type);
    // bcs serialzies u64 as 8 bytes
    payload.append(reverse_bytes(bcs::to_bytes(&amount)));

```
