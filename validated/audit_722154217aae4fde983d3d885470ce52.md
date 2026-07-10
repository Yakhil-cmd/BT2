### Title
Echo-Broadcast Threshold Collapses to Zero for Small Participant Sets, Enabling Equivocation During DKG — (`File: src/protocol/echo_broadcast.rs`)

---

### Summary

The `echo_ready_thresholds` function unconditionally returns `(0, 0)` for any participant count `n ≤ 3`. Because the protocol advances phases by checking `count > threshold`, a threshold of `0` means a single self-simulated vote immediately satisfies every phase gate. A malicious participant can therefore send different polynomial commitments to different honest parties during DKG, and each honest party will deliver its own inconsistent value without waiting for agreement — corrupting the DKG output.

---

### Finding Description

In `src/protocol/echo_broadcast.rs`, the threshold computation is:

```rust
fn echo_ready_thresholds(n: usize) -> (usize, usize) {
    if n <= 3 {
        return (0, 0);   // echo_t = 0, ready_t = 0
    }
    let broadcast_threshold = (n - 1) / 3;
    let echo_threshold = usize::midpoint(n, broadcast_threshold);
    (echo_threshold, broadcast_threshold)
}
``` [1](#0-0) 

These two values drive every phase gate in `reliable_broadcast_receive_all`:

| Phase | Condition | With threshold = 0 |
|---|---|---|
| Echo → Ready | `count > echo_t` | `count > 0` — satisfied by the single self-simulated echo |
| Ready amplification | `count > ready_t` | `count > 0` — satisfied by the single self-simulated ready |
| Ready delivery | `count > 2 * ready_t` | `count > 0` — satisfied by the single self-simulated ready | [2](#0-1) [3](#0-2) 

Because the simulated self-vote is injected immediately upon receiving a `Send` message, every honest party with `n ≤ 3` delivers whatever the sender addressed to it — without waiting for any corroborating echo or ready from any other party.

The DKG (`keygen`, `reshare`, `refresh`) explicitly allows `n = 3` with `threshold = 2`:

```rust
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [4](#0-3) 

A 3-of-3 or 2-of-3 DKG is a fully supported and documented configuration, yet the echo-broadcast used inside it provides zero equivocation protection.

---

### Impact Explanation

During DKG, each participant broadcasts its polynomial commitment `C_i` via `do_broadcast`, which internally calls `reliable_broadcast_receive_all`. [5](#0-4) 

A malicious participant `A` (acting as the sender for its own broadcast session) sends `Send(C_fake_1)` to honest party `B` and `Send(C_fake_2)` to honest party `C`. With `echo_t = ready_t = 0`:

1. `B` receives `Send(C_fake_1)`, simulates its own echo, immediately satisfies `count > 0`, sends `Ready(C_fake_1)`, simulates its own ready, immediately satisfies `count > 0`, and **delivers `C_fake_1`**.
2. `C` receives `Send(C_fake_2)`, follows the same path, and **delivers `C_fake_2`**.

`B` and `C` now hold different views of `A`'s commitment. They compute different aggregate public keys (`pk = Σ C_j(0)`), so the DKG produces inconsistent `KeygenOutput` values across honest parties — the key material is permanently corrupted and unusable for threshold signing.

This maps directly to the allowed High impact: **Corruption of DKG outputs so honest parties accept inconsistent public keys or unusable cryptographic outputs**.

---

### Likelihood Explanation

- The minimum supported DKG configuration is `n = 2, threshold = 2`, and `n = 3, threshold = 2` is explicitly tested and documented as valid.
- Any participant in a 3-party DKG is a potential attacker; no external capability beyond participation is required.
- The attack requires only that the malicious party send different `Send` messages to different recipients — a straightforward network-layer manipulation available to any participant who controls their own outgoing messages.
- The `n = 3` case is the most common small-group deployment (e.g., 2-of-3 multisig wallets), making this a realistic and high-probability attack scenario.

---

### Recommendation

Replace the hard-coded `(0, 0)` early return with a minimum of `(1, 1)` (or the correct formula for `n = 3`), so that at least one external corroborating echo/ready is required before advancing phases, even for small participant sets:

```rust
fn echo_ready_thresholds(n: usize) -> (usize, usize) {
    // Require at least 1 external corroborating vote even for small n
    if n <= 3 {
        return (1, 1);
    }
    let broadcast_threshold = (n - 1) / 3;
    let echo_threshold = usize::midpoint(n, broadcast_threshold);
    (echo_threshold, broadcast_threshold)
}
```

Alternatively, enforce at the DKG initialization layer that `n >= 4` whenever malicious-party tolerance is desired, and document that `n ≤ 3` configurations assume all participants are honest.

---

### Proof of Concept

With `n = 3` participants `[A, B, C]` and `threshold = 2`:

1. `A` is malicious. It calls `reliable_broadcast_send` normally (sending `Send(C_A)` to all), but for its own broadcast session it sends `Send(C_fake_1)` to `B` and `Send(C_fake_2)` to `C` via direct channel manipulation.
2. `B` receives `Send(C_fake_1)`:
   - `echo_ready_thresholds(3)` returns `(0, 0)`.
   - Simulated self-echo: `data_echo[C_fake_1] = 1`. Check `1 > 0` → **TRUE** → sends `Ready(C_fake_1)`.
   - Simulated self-ready: `data_ready[C_fake_1] = 1`. Check `1 > 0` → **TRUE** → amplifies. Check `1 > 0` → **TRUE** → **delivers `C_fake_1`**.
3. `C` receives `Send(C_fake_2)` and by the same path **delivers `C_fake_2`**.
4. `B` computes `pk_B = C_fake_1(0) + C_B(0) + C_C(0)` and `C` computes `pk_C = C_fake_2(0) + C_B(0) + C_C(0)`.
5. `pk_B ≠ pk_C` — the DKG is corrupted. [1](#0-0) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** src/protocol/echo_broadcast.rs (L67-78)
```rust
fn echo_ready_thresholds(n: usize) -> (usize, usize) {
    // case where no malicious parties are assumed: when n <= 3/
    // In this case the echo and ready thresholds are both 0
    // later we compare if we have collected more votes than these thresholds
    if n <= 3 {
        return (0, 0);
    }
    // we should always have n >= 3*threshold + 1
    let broadcast_threshold = (n - 1) / 3;
    let echo_threshold = usize::midpoint(n, broadcast_threshold);
    (echo_threshold, broadcast_threshold)
}
```

**File:** src/protocol/echo_broadcast.rs (L150-152)
```rust
    let n = participants.len();
    let (echo_t, ready_t) = echo_ready_thresholds(n);

```

**File:** src/protocol/echo_broadcast.rs (L221-235)
```rust
                // upon gathering strictly more than (n+f)/2 votes
                // for a result, deliver Ready.
                if state_sid.data_echo.get(&data).ok_or_else(|| {
                    ProtocolError::Other("Missing element in CounterList".to_string())
                })? > echo_t
                {
                    vote = MessageType::Ready(data);
                    chan.send_many(wait, &(&sid, &vote))?;
                    // state that the echo phase for session id (sid) is done
                    state_sid.finish_echo = true;

                    // simulate a ready vote sent by me
                    is_simulated_vote = true;
                    from = me;
                }
```

**File:** src/protocol/echo_broadcast.rs (L280-295)
```rust
                if state_sid.data_ready.get(&data).ok_or_else(|| {
                    ProtocolError::Other("Missing element in CounterList".to_string())
                })? > ready_t
                    && !state_sid.finish_amplification
                {
                    vote = MessageType::Ready(data.clone());
                    chan.send_many(wait, &(&sid, &vote))?;
                    state_sid.finish_amplification = true;

                    // simulate a ready vote sent by me
                    is_simulated_vote = true;
                    from = me;
                }
                if state_sid.data_ready.get(&data).ok_or_else(|| {
                    ProtocolError::Other("Missing element in CounterList".to_string())
                })? > 2 * ready_t
```

**File:** src/dkg.rs (L9-11)
```rust
use crate::protocol::{
    echo_broadcast::do_broadcast, helpers::recv_from_others, internal::SharedChannel,
};
```

**File:** src/dkg.rs (L580-582)
```rust
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
    }
```
