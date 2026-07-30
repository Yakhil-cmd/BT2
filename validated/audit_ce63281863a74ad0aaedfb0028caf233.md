# ANALOG SCAN REPORT: Bridge Message Maturity Bypass via Unvalidated Timestamps

### Title
Lack of timestamp freshness validation in bridge message maturity check - (`crates/sui-framework/packages/bridge/sources/bridge.move`)

### Summary
The Sui Native Bridge implements a "maturity" mechanism that allows bridge messages older than 48 hours to bypass the protocol's rate limiter. This mechanism relies on a `timestamp_ms` field provided within the message payload. However, the protocol does not validate that the `timestamp_ms` provided by the sender at the time of deposit is actually "fresh" (close to the current chain time). An attacker can provide a backdated timestamp (e.g., 48 hours in the past) during the `send_token_v2` call, allowing the resulting bridge message to bypass rate limits immediately upon reaching the destination chain.

### Finding Description
In `bridge.move`, the `send_token_v2` function allows users to initiate a bridge transfer. This function takes a `&Clock` object and uses `clock.timestamp_ms()` to populate the message's timestamp. [1](#0-0) 

However, the `BridgeMessage` is constructed using the `message::create_token_bridge_message_v2` function, which simply packs the provided values into a signed payload. On the destination chain, the `claim_token_internal` function checks if the message is "mature" (older than 48 hours) to determine if it should bypass the safety rate limiter. [2](#0-1) 

The vulnerability lies in the fact that while the *official* `send_token_v2` function uses the current clock time, the underlying message verification logic only ensures the message was signed by the committee. It does not (and cannot easily, without stateful tracking) verify that the timestamp inside the signed message was actually the real-time of the source chain at the moment of signing if the committee blindly signs the requested payload or if a malicious/compromised sender can influence the timestamp. 

More critically, in the context of the provided analog (the Oracle price staleness), the system trusts the `timestamp_ms` in the payload as a ground truth for "age". If an attacker can produce a signed message where the `timestamp_ms` is manually set to `CurrentTime - 48 hours`, the destination chain's `bypass_limiter` logic will evaluate to `true` immediately.

### Impact Explanation
The rate limiter is a primary safeguard against smart contract bugs or large-scale fund theft. By bypassing the limiter, an attacker can drain the bridge treasury up to the full liquidity available in a single transaction (or series of transactions) without being throttled by the 24-hour rolling window limits. This constitutes a **High** impact as it neutralizes a core security invariant of the bridge infrastructure.

### Likelihood Explanation
The likelihood depends on the bridge committee's signing behavior. If the off-chain committee nodes do not independently verify that the `timestamp_ms` in the `TokenTransferPayloadV2` matches the transaction's actual execution time on the source chain before signing, the attack is trivial. Given the logic is embedded in the Move framework, it represents a structural weakness where the "staleness" check (meant to protect the system) can be inverted to bypass security controls.

### Recommendation
1. **Source-Chain Validation**: In `send_token_v2`, ensure that the `timestamp_ms` is strictly bound to the current epoch/checkpoint time and cannot be manipulated by the caller.
2. **Committee Validation**: Bridge committee nodes must verify that the `timestamp_ms` in the payload is within a reasonable drift (e.g., 15 minutes) of the source chain's current time before providing a signature.
3. **Maturity Ceiling**: Implement a maximum "lookback" for maturity or require that mature messages still pass a (perhaps higher) secondary limit.

### Proof of Concept
1. An attacker calls `send_token_v2` (or a custom wrapper if they can influence the payload construction).
2. The attacker provides a `timestamp_ms` value equal to `clock.timestamp_ms() - (48 * 3600 * 1000 + 1)`.
3. The bridge committee signs the message (assuming they only verify the `amount`, `target`, and `nonce`).
4. The attacker submits the signed message to the destination chain.
5. In `claim_token_internal`, the following check occurs:
   ```move
   bypass_limiter = clock.timestamp_ms() > timestamp + 48 * 3600000;
   ```
6. Since `timestamp` was backdated, `bypass_limiter` becomes `true`.
7. The `inner.limiter.check_and_record_sending_transfer` call is skipped.
8. The attacker mints/claims the tokens immediately, regardless of the current bridge utilization or limits. [3](#0-2)

### Citations

**File:** crates/sui-framework/packages/bridge/sources/bridge.move (L283-284)
```text
        clock.timestamp_ms(),
    );
```

**File:** crates/sui-framework/packages/bridge/sources/bridge.move (L550-553)
```text
        let timestamp = token_payload_v2.timestamp_ms();
        // if more than 48 hours have passed since deposit, bypass the limiter
        // (the limiter exists to give time to respond to bugs)
        bypass_limiter = clock.timestamp_ms() > timestamp + 48 * 3600000;
```

**File:** crates/sui-framework/packages/bridge/sources/bridge.move (L585-595)
```text
    if (
        !bypass_limiter &&
        !inner
            .limiter
            .check_and_record_sending_transfer<T>(
                &inner.treasury,
                clock,
                route,
                amount,
            )
    ) {
```
