### Title
Share price can be permanently skewed via a `totalSupply = 0`, `totalAssets != 0` state, freezing subsequent depositors' funds — ([File: mainnet/contracts/vault/v0-vault-usdc.clar])

### Summary
Every Zest v2 tokenized vault (`v0-vault-usdc.clar`, `v0-vault-stx.clar`, `v0-vault-sbtc.clar`, `v0-vault-ststx.clar`, `v0-vault-ststxbtc.clar`, `v0-vault-usdh.clar`) implements the same ERC4626-style share math with the exact "1:1 on empty supply" fallback that caused the reported Morpho `VaultV2` bug. When `total-supply-preview` returns `u0` while `total-assets-preview`/`var-get assets` is still non-zero (which floor-rounding in `redeem` makes reachable), the next depositor mints shares 1:1 against the deposited amount while ignoring the outstanding non-zero asset balance, permanently skewing the share-to-asset exchange rate against every subsequent, unrelated depositor.

### Finding Description
`convert-to-shares-preview` mints shares 1:1 whenever the (previewed) total supply is zero, irrespective of whether `total-assets-preview` is also zero: [1](#0-0) 

`redeem` computes the assets to return via `convert-to-assets-preview`, which uses `mul-div-down` (floor rounding) and then subtracts that from `current-assets` (`var-get assets`): [2](#0-1) 

Because `convert-to-assets-preview` rounds down, a redeemer who burns 100% of the outstanding `zft` supply can receive `floor(balance * ta / ts)` assets that is strictly less than `ta` by up to 1 unit of dust, per‑vault, per‑zero‑crossing event. After this transfer, `ft-get-supply zft` becomes `u0` while `var-get assets` (and therefore `total-assets-preview`) retains that dust. Because `next-index`/interest math is separately compounding on `total-borrowed`/`principal-scaled`, the same rounding leak can compound each time supply is driven back to zero (analogous to the PoC in the report, where `deallocate`/`redeem` left `ta = 1` while `ts = 0`).

Once this state (`ts = 0`, `ta != 0`) exists, `convert-to-shares-preview` takes the `(is-eq ts u0)` branch and returns `amount` (1:1) for the next `deposit`, completely ignoring the dust already sitting in `assets`. The depositor who happens to trigger that first post-zero deposit gets shares worth `(assets_dust + deposited_amount)` for a mint of only `deposited_amount` shares. Every subsequent, unrelated depositor is now diluted: their `previewDeposit`/actual shares received via the same `convert-to-shares-preview` are computed against an inflated `ta` per share, and if their deposit amount is smaller than the dust-inflated `ta`, `mul-div-down` can floor their shares to `u0`, which is rejected by the `ERR-SLIPPAGE`/`min-out` check in `deposit`, freezing their ability to deposit at all until the skew is manually fixed.

### Impact Explanation
This is not "ordinary shared-pool economics" — it is a state (`assets` var / `total-supply`) written by whichever principal happens to be the first depositor/redeemer to cross the `ts = 0` boundary, and it is then involuntarily consumed by every later, unrelated depositor, who receives fewer shares than their deposit is worth (or is blocked from depositing via slippage revert). That is a stranger harming a stranger through a shared index primed by a prior caller — in scope per the rules ("a shared index or cache primed by one caller and consumed by another"). The resulting economic loss/inability to deposit is a temporary freezing of user funds (their capital is stuck outside the vault, unable to be deposited at fair value), which maps to the in-scope **High** impact class ("temporary freezing of funds").

### Likelihood Explanation
Requires driving `total-supply` fully to zero while there is still an `assets`/`total-assets` remainder — achievable whenever the last holder(s) fully redeem (rounding dust is essentially guaranteed for any redemption ratio that isn't an exact divisor), or whenever `fee-reserve`/interest math leaves untouched dust after the pool is fully drained. No special privilege is required; any user (or the last two cooperating/uncoordinated redeemers) can trigger it, and it becomes a standing trap for the next ordinary depositor. Likelihood is low-to-medium since it needs the vault to reach zero total supply, which is more likely on newly deployed, low-TVL, or niche vaults (e.g., `v0-vault-ststxbtc`).

### Recommendation
- Do not special-case `ts = 0` to a naive 1:1 mint. Instead, permanently seed each vault with a minimal, unrecoverable/dead-address share balance at deployment (i.e., mint dust shares to a burn address) so `total-supply` can never return to zero while `assets > 0`.
- Alternatively, apply a virtual-shares/virtual-assets offset (as done in fixed OpenZeppelin/Morpho ERC4626 implementations) in `convert-to-shares-preview`/`convert-to-assets-preview`, e.g. compute ratios using `(ts + OFFSET)` and `(ta + OFFSET)` so the zero-supply branch is never independently reachable.
- Add an invariant test/fuzz check ensuring `total-supply-preview() == 0 ⇒ total-assets-preview() == 0` (and vice versa) across `deposit`/`redeem`/`accrue` sequences for all six vault contracts.

### Proof of Concept
1. Deploy `v0-vault-usdc` (or any vault) fresh; Alice deposits `amount` USDC, receiving `amount` shares 1:1 (empty vault).
2. Time passes, interest accrues (`total-assets-preview` grows via `debt-preview`/`total-borrowed` in `total-assets-preview`, see `total-assets-preview` at [3](#0-2) ).
3. Alice calls `redeem` with her full share balance. `inkind = convert-to-assets-preview(balance)` rounds down via `mul-div-down`, so `current-assets - inkind` leaves 1+ wei of dust in `var-get assets`, while `ft-burn?` drives `total-supply` to `u0`.
4. Now `ts = 0`, `ta = dust > 0`.
5. Bob deposits `amount2` USDC. `convert-to-shares-preview` takes the `is-eq ts u0` branch and returns `amount2` shares 1:1, ignoring the `dust` already present, so Bob's shares are now worth `(dust + amount2)` — Bob is temporarily over-credited, but every subsequent unrelated depositor (Carol) computes shares against the now-skewed `ta/ts` ratio, and if `Carol`'s deposit is small relative to the (now inflated) per-share asset value, `convert-to-shares-preview` floors her mint to `u0`, tripping `ERR-SLIPPAGE` in `deposit` and blocking her from depositing at fair value — freezing her funds outside the vault until the skew is corrected.

### Citations

**File:** mainnet/contracts/vault/v0-vault-usdc.clar (L306-313)
```text
(define-private (convert-to-shares-preview (amount uint))
  (let ((ta (total-assets-preview))
        (ts (total-supply-preview)))
    (if (is-eq ts u0)
        amount
        (if (is-eq ta u0)
            u0
            (mul-div-down amount ts ta)))))
```

**File:** mainnet/contracts/vault/v0-vault-usdc.clar (L339-345)
```text
(define-private (total-assets-preview)
  (let ((current-assets (var-get assets))
        (debt (debt-preview))
        (borrowed (var-get total-borrowed))
        (interest (if (> debt borrowed) (- debt borrowed) u0)))
    (+ current-assets interest)))

```

**File:** mainnet/contracts/vault/v0-vault-usdc.clar (L799-810)
```text
    (account contract-caller)
    (current-assets (var-get assets))
    (balance (get-balance-internal account))
    (balance-check (asserts! (>= balance amount) ERR-INSUFFICIENT-BALANCE))
    (available-assets (get-available-assets))
    (inkind (convert-to-assets-preview amount)))

  (asserts! (>= current-assets inkind) ERR-INSUFFICIENT-ASSETS)
  (asserts! (not (get redeem states)) ERR-PAUSED)
  (asserts! (> amount u0) ERR-AMOUNT-ZERO)
  (asserts! (> inkind u0) ERR-OUTPUT-ZERO)
  (asserts! (>= inkind min-out) ERR-SLIPPAGE)
```
