### Title
Donation-attack breaks initial-deposit bootstrap and permanently freezes funds in the Uniswap-like market-maker AA template - (File: `test/samples/uniswap_like_market_maker.oscript`)

### Summary
The bundled market-maker AA template computes share issuance and swap ratios from the AA's raw on-chain balances (`balance[$asset]`, `balance[base]`) rather than from an internally accounted "total invested" figure, exactly like the Sherlock finding where `DnGmxSeniorVault.totalAssets()` read `aUsdc.balanceOf(address(this))` directly. Any unprivileged user can send a plain payment to the AA address that does not satisfy any of the defined `if` cases, silently inflating `balance[base]` without updating `var['mm_asset_outstanding']`. This corrupts the "is this the initial deposit" check used by the real first investor, causing loss/freezing of funds.

### Finding Description
The AA's "invest" case decides whether it is the very first deposit purely by checking whether the *raw* balances (net of the current trigger's own outputs) are zero:
```
$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
$bytes_balance = balance[base] - trigger.output[[asset=base]];
if ($asset_balance == 0 OR $bytes_balance == 0){ // initial deposit
    $issue_amount = balance[base];
    return;
}
``` [1](#0-0) 

Because none of the AA's `if` conditions in the "invest" (`trigger.output[[asset=$asset]] > 0`), "divest" (`trigger.output[[asset=$mm_asset]]`), or "exchange" (`var['mm_asset_outstanding']` truthy) cases match a plain, unsolicited payment of only base bytes (below the exchange threshold or without a paired asset amount), any attacker can send raw bytes to the AA address and have them silently absorbed into `balance[base]` while `var['mm_asset_outstanding']` stays at `0`.

When the real first investor later deposits both `$asset` and `base` together, `$bytes_balance` is no longer `0` (because of the attacker's donation), so the code skips the "initial deposit" branch and instead computes:
```
$current_ratio = $asset_balance / $bytes_balance;
$expected_asset_amount = round($current_ratio * trigger.output[[asset=base]]);
if ($expected_asset_amount != trigger.output[[asset=$asset]])
    bounce('wrong ratio of amounts, expected ' || $expected_asset_amount || ' of asset');
$investor_share_of_prev_balance = trigger.output[[asset=base]] / $bytes_balance;
$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding']);
``` [2](#0-1) 

Since no `$asset` was ever actually deposited (`$asset_balance == 0`), `$current_ratio` evaluates to `0`, forcing `$expected_asset_amount` to `0`. The real investor's non-zero `$asset` output then fails the equality check and the trigger bounces. Even in a variant where the check passes, `$issue_amount = round(share * var['mm_asset_outstanding'])` with `var['mm_asset_outstanding'] == 0` always yields `0`, so a legitimate investor can be made to deposit real value and receive `0` `mm_asset` shares while the attacker's donated bytes and the investor's own funds remain trapped in the AA balance with no code path (`divest`, `exchange`) able to release them, because those paths are gated on `var['mm_asset_outstanding']` being non-zero.

This mirrors the core root cause of the reported Solidity bug class: using a directly-observable, externally-manipulable balance (`balance[...]` in `oscript`, `aUsdc.balanceOf(...)` in Solidity) instead of an internally tracked accounting variable to compute share/ratio math, letting a donation before the first legitimate deposit corrupt or lock down subsequent accounting.

### Impact Explanation
An attacker can permanently freeze the bootstrap of a market-maker AA deployed from this template: any base-token donation sent before real capital is deposited corrupts the "initial deposit" detection, bricking the AA's `invest`/`divest`/`exchange` logic (which all require `var['mm_asset_outstanding']` to be truthy) and freezing both the attacker's donated funds and any subsequent investor deposits that get bounced/mis-priced. This falls under "AA fund loss or freezing."

### Likelihood Explanation
The attack requires only a single, unprivileged unit sending a normal payment to the AA's address before the intended first investor deposits — no special privileges, front-running of specific mempool transactions is trivial since AA addresses are public immediately after `trigger.data.define` is processed and before any real investment occurs.

### Recommendation
Do not derive the "initial deposit" branch or ratio calculations from raw `balance[...]` reads. Track total invested/outstanding amounts entirely via internal state variables (as is already correctly done for `$mm_asset_outstanding` on the issuance side), and detect "is this the first deposit" using a dedicated state flag (e.g., `var['initialized']`) rather than `balance[$asset] == 0 OR balance[base] == 0`, which can be manipulated by any direct transfer to the AA address.

### Proof of Concept
1. Attacker triggers `trigger.data.define` to create `$mm_asset` (state var `mm_asset` set, `mm_asset_outstanding` unset/`0`).
2. Attacker sends a plain payment of, say, `200000` bytes to the AA address with no matching trigger data/asset output — this fails every `if` condition (`invest` needs `$asset` output `>0`; `divest` needs `mm_asset` output; `exchange` cases need `var['mm_asset_outstanding']` truthy) so the AA takes no action, and the bytes are silently absorbed into `balance[base]`. [3](#0-2) 
3. A legitimate investor now sends the paired `$asset` and `base` outputs intending to make the "initial deposit." Because `balance[base] - trigger.output[[asset=base]]` (i.e., the attacker's donated bytes) is no longer `0`, the code skips the initial-deposit branch, computes `$current_ratio = 0` (since `$asset_balance == 0`), and either bounces the investor's transaction or issues `0` `mm_asset` shares while accepting their real `$asset`/`base` deposit. [4](#0-3) 
4. Result: attacker's donated bytes and the investor's deposited funds sit in the AA balance with no `divest`/`exchange` path able to release them (all gated on `var['mm_asset_outstanding']` being non-zero), permanently freezing funds.

### Citations

**File:** test/samples/uniswap_like_market_maker.oscript (L33-34)
```text
			{ // invest in MM
				if: `{$mm_asset AND trigger.output[[asset=base]] > 1e5 AND trigger.output[[asset=$asset]] > 0}`,
```

**File:** test/samples/uniswap_like_market_maker.oscript (L36-47)
```text
					$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
					$bytes_balance = balance[base] - trigger.output[[asset=base]];
					if ($asset_balance == 0 OR $bytes_balance == 0){ // initial deposit
						$issue_amount = balance[base];
						return;
					}
					$current_ratio = $asset_balance / $bytes_balance;
					$expected_asset_amount = round($current_ratio * trigger.output[[asset=base]]);
					if ($expected_asset_amount != trigger.output[[asset=$asset]])
						bounce('wrong ratio of amounts, expected ' || $expected_asset_amount || ' of asset');
					$investor_share_of_prev_balance = trigger.output[[asset=base]] / $bytes_balance;
					$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding']);
```
