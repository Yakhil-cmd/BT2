Audit Report

## Title
SNS Treasury Valuation Manipulation via Live Swap Derived State Inflating `icps_per_token` — (`rs/sns/governance/token_valuation/src/lib.rs`)

## Summary

`IcpsPerSnsTokenClient::fetch_icps_per_sns_token` queries the swap canister's `get_derived_state` endpoint to obtain a live, mutable `sns_tokens_per_icp` value during an open swap. An unprivileged attacker can deposit a large ICP amount into the open swap to deflate `sns_tokens_per_icp`, which inflates `icps_per_token`, which inflates the treasury's XDR valuation, pushing it into the "large" regime and imposing a hard 300,000 XDR cap on 7-day treasury transfers. Legitimate `TransferSnsTreasuryFunds` proposals exceeding that cap are rejected at submission time. The attacker recovers their ICP after the swap closes or aborts, making this a low-cost, repeatable governance DoS.

## Finding Description

`fetch_icps_per_sns_token` issues a canister call to `get_derived_state` on the swap canister:

```rust
call::<_, MyRuntime>(self.swap_canister_id, GetDerivedStateRequest {})
``` [1](#0-0) 

The swap canister's `derived_state()` computes `sns_tokens_per_icp` from the **live** `participant_total_icp_e8s`, which changes with every ICP deposit during an open swap:

```rust
let sns_tokens_per_icp = i2d(tokens_available_for_swap)
    .checked_div(i2d(participant_total_icp_e8s))
    .and_then(|d| d.to_f32())
    .unwrap_or(0.0);
``` [2](#0-1) 

This is exposed as a `#[query]` endpoint with no access control: [3](#0-2) 

The governance valuation code inverts this to get `icps_per_token`: [4](#0-3) 

The resulting `icps_per_token` feeds directly into the XDR valuation: [5](#0-4) 

`clamp_xdrs_per_icp` only enforces a floor on `xdrs_per_icp`; there is no clamp on `icps_per_token` and no `MAX_XDRS_PER_ICP`: [6](#0-5) [7](#0-6) 

The valuation is locked into the proposal at submission time: [8](#0-7) 

And the same locked valuation is reused at execution time: [9](#0-8) 

The three transfer regimes are: [10](#0-9) 

**Exploit path (Attack A — griefing, no governance majority required):**
1. An SNS swap is open. Treasury holds T SNS tokens. Normal `icps_per_token` = P.
2. Attacker deposits a large ICP amount D into the swap, inflating `buyer_total_icp_e8s` by D, deflating `sns_tokens_per_icp` by factor k, inflating `icps_per_token` to k·P.
3. A legitimate `TransferSnsTreasuryFunds` proposal is submitted. The valuation call reads the live derived state and computes `T * k*P * xdrs_per_icp > 1,200,000 XDR`.
4. The proposal is subject to the 300,000 XDR hard cap. If the intended transfer exceeds this cap, the proposal is rejected at submission.
5. After the swap closes or aborts, the attacker reclaims their ICP. The SNS governance is blocked for the duration of the swap lifecycle.

**Attack B (bypassing limits)** requires a governance majority in the SNS and is out of scope per the rejection rules.

## Impact Explanation

Attack A is a concrete, capital-recoverable DoS on SNS governance treasury transfers. Any SNS with an open swap is vulnerable: an unprivileged external participant can suppress legitimate `TransferSnsTreasuryFunds` proposals for the entire duration of the swap (days to weeks) by temporarily inflating the treasury's apparent XDR valuation. This matches **High ($2,000–$10,000): Significant SNS security impact with concrete user or protocol harm** — specifically, governance-level DoS that prevents authorized treasury actions from being submitted or executed during the attack window.

## Likelihood Explanation

- Requires an open SNS swap (common during SNS launches, lasting days to weeks).
- Requires enough ICP to meaningfully shift `buyer_total_icp_e8s` relative to existing participation — capital-intensive but fully recoverable after swap close/abort.
- No governance majority or special privilege required; any external participant can execute this.
- Attack is repeatable across every SNS launch that uses the standard swap canister.
- Attacker must time the deposit to precede proposal submission, which is observable on-chain.

## Recommendation

1. **Use the finalized swap price, not the live derived state.** After `finalize_swap`, the swap canister stores immutable `buyer_total_icp_e8s` and `sns_token_e8s`. The governance canister should read the committed final price from the swap's finalized state rather than calling `get_derived_state` on a potentially open swap.

2. **Add a `MAX_ICPS_PER_TOKEN` clamp** in `fetch_icps_per_sns_token` (analogous to `MIN_XDRS_PER_ICP`) to bound the maximum `icps_per_token` to a realistic ceiling, preventing extreme valuation inflation from manipulated swap state.

3. **Add a `MAX_XDRS_PER_ICP` clamp** in `clamp_xdrs_per_icp` to symmetrically bound the XDR/ICP rate and prevent the combined product from reaching unrealistic valuations.

## Proof of Concept

1. Deploy a local SNS with swap open, 1,000,000 SNS tokens available, 100,000 ICP deposited → `sns_tokens_per_icp = 10.0`, `icps_per_token = 0.1`. Treasury holds 1,000,000 SNS tokens. Valuation = `1,000,000 * 0.1 * 10 = 1,000,000 XDR` → medium regime (25% cap = 250,000 tokens).
2. Attacker calls `refresh_buyer_tokens` depositing 9,900,000 ICP → `buyer_total_icp_e8s = 10,000,000`, `sns_tokens_per_icp = 0.1`, `icps_per_token = 10.0`.
3. Submit a `TransferSnsTreasuryFunds` proposal for 200,000 SNS tokens (worth ~200,000 XDR at true price, well within the 25% cap). The governance canister calls `get_derived_state`, reads `sns_tokens_per_icp = 0.1`, computes valuation = `1,000,000 * 10 * 10 = 100,000,000 XDR` → large regime, 300,000 XDR cap = 30,000 tokens. Proposal is rejected at submission because 200,000 > 30,000 tokens.
4. Attacker withdraws ICP after swap abort. SNS governance is paralyzed for the swap duration.

A deterministic integration test using PocketIC can reproduce this by: (a) initializing an SNS swap, (b) calling `refresh_buyer_tokens` with a large ICP amount from an attacker principal, (c) calling `validate_and_render_transfer_sns_treasury_funds` with a transfer amount between the true 25%-cap and the inflated 300,000-XDR cap, and (d) asserting the proposal is rejected with a limit-exceeded error.

### Citations

**File:** rs/sns/governance/token_valuation/src/lib.rs (L118-126)
```rust
    pub fn to_xdr(&self) -> Decimal {
        let Self {
            tokens,
            icps_per_token,
            xdrs_per_icp,
        } = self;

        tokens * icps_per_token * xdrs_per_icp
    }
```

**File:** rs/sns/governance/token_valuation/src/lib.rs (L316-318)
```rust
        let (get_derived_state_result, initial_supply_e8s_result, current_supply_result) = join!(
            // 1. SNS token price from swap.
            call::<_, MyRuntime>(self.swap_canister_id, GetDerivedStateRequest {}),
```

**File:** rs/sns/governance/token_valuation/src/lib.rs (L389-395)
```rust
        let initial_icps_per_sns_token = Decimal::from(1)
            .checked_div(initial_sns_tokens_per_icp)
            .ok_or_else(|| {
            ValuationError::new_arithmetic(format!(
                "Unable to perform 1 / sns_tokens_per_icp (where sns_tokens_per_icp = {initial_sns_tokens_per_icp}).",
            ))
        })?;
```

**File:** rs/sns/swap/src/swap.rs (L2992-2995)
```rust
        let sns_tokens_per_icp = i2d(tokens_available_for_swap)
            .checked_div(i2d(participant_total_icp_e8s))
            .and_then(|d| d.to_f32())
            .unwrap_or(0.0);
```

**File:** rs/sns/swap/canister/canister.rs (L219-223)
```rust
#[query]
async fn get_derived_state(_request: GetDerivedStateRequest) -> GetDerivedStateResponse {
    log!(INFO, "get_derived_state");
    swap().derived_state().into()
}
```

**File:** rs/sns/governance/proposals_amount_total_limit/src/lib.rs (L60-64)
```rust
    /// # Why Not Also Define MAX?
    ///
    /// Currently, we do not have/enforce a MAX_XDRS_PER_ICP, because this would tend to cause our
    /// valuations to be in the "large" regime, where actions are more limited.
    const MIN_XDRS_PER_ICP: Decimal = dec!(1);
```

**File:** rs/sns/governance/proposals_amount_total_limit/src/lib.rs (L126-134)
```rust
        if valuation_xdr <= Self::MAX_SMALL_TREASURY_SIZE_XDR {
            return Self::NoLimit;
        }

        if valuation_xdr <= Self::MAX_MEDIUM_TREASURY_SIZE_XDR {
            return Self::Fraction(ONE_QUARTER);
        }

        Self::Xdr(Self::MAX_XDR)
```

**File:** rs/sns/governance/proposals_amount_total_limit/src/lib.rs (L137-140)
```rust
    fn clamp_xdrs_per_icp(valuation: &mut Valuation) {
        let xdrs_per_icp = &mut valuation.valuation_factors.xdrs_per_icp;
        *xdrs_per_icp = (*xdrs_per_icp).max(Self::MIN_XDRS_PER_ICP);
    }
```

**File:** rs/sns/governance/src/proposal.rs (L591-594)
```rust
                Some(valuation) => Ok((
                    rendering,
                    ActionAuxiliary::TransferSnsTreasuryFunds(valuation),
                )),
```

**File:** rs/sns/governance/src/governance.rs (L3000-3005)
```rust
        transfer_sns_treasury_funds_amount_is_small_enough_at_execution_time_or_err(
            transfer,
            valuation?,
            self.proto.proposals.values(),
            self.env.now(),
        )?;
```
