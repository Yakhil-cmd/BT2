### Title
Irreversible `auto_destroy` Asset State Prevents the Definer From Ever Spending Funds Sent to Its Own Address - ([File: validation.js])

### Summary
An asset can be created with `auto_destroy: true`. Once any output of that asset is sent to the `definer_address` of the asset, the funds become permanently unspendable by anyone, including the definer, because `validatePaymentInputsAndOutputs()` unconditionally rejects any attempt to spend an input owned by `objAsset.definer_address` for such assets. This mirrors the reported analog bug class: a one-way, irreversible state transition (triggered by an ordinary, unprivileged unit poster sending a payment) permanently locks funds with no code path to reverse it — exactly like the Curve-pool-killed / `emergencyExit` deadlock, where a state toggle becomes impossible to undo once an external/irreversible condition is hit.

### Finding Description
When validating a payment of a divisible or indivisible asset, ocore checks whether the asset has `auto_destroy` set and whether the address that owns the spent output is the asset's `definer_address`. If so, the input is rejected outright with "this output was destroyed by sending to definer address" — there is no exception, no alternate path, and no way to reclaim or re-spend those funds: [1](#0-0) [2](#0-1) 

This check fires for both the "transfer" (spending a previous output, `src_coin` case) and the standard input-lookup case, covering both public and private payment paths (`validatePaymentInputsAndOutputs` is used for base and asset payments alike, including private/hidden payments through `indivisible_asset.js`/`divisible_asset.js`).

Crucially, **anyone** (an unprivileged unit poster or AA trigger sender) can construct a payment that sends `auto_destroy`-enabled asset tokens to the `definer_address` — this is a normal, permitted payment output, not a privileged action. Because "auto_destroy" is meant as an intentional "burn" mechanism (funds sent to the definer's address are supposed to be destroyed/burned), this is by design for outputs the definer never needs back. However, the same mechanism creates a real deadlock scenario:

- If the `definer_address` is itself an Autonomous Agent (AA) — a common pattern for AAs that issue their own capped/managed tokens (see `issue_amount`/`issued_by_definer_only` patterns in `aa_composer.js`) — and the AA's own logic (or an external actor) ever causes a payment of that asset to flow back to the AA's own address as part of an otherwise valid operational flow (e.g., an incorrect/legacy state transition, a bounced-and-retried operation, or a bug in an unrelated part of the AA's message logic that references `this_address` as a payment recipient for its own asset), those tokens become permanently frozen inside the AA. The AA can never spend them out again: any attempt to build an outgoing payment consuming that specific output fails validation with the "destroyed" error, exactly like `emergencyExit`/`restoreVault` becoming mutually unusable once the Curve pool is killed.
- Because the check is enforced purely based on `owner_address === objAsset.definer_address`, an unprivileged trigger sender can deliberately engineer a griefing payment that sends `auto_destroy` tokens the AA is expecting to eventually redistribute back to the AA's own address (e.g., in a payment/refund loop, self-referential balance rebalancing, or any AA logic path that legitimately expects to reuse its own previously-issued and returned tokens) to permanently strand value that the AA (and hence its users) can never recover.

This is analogous to the Sherlock report's core defect: a state flag (`is_killed` on the Curve pool / "destroyed" ownership by definer) can be irreversibly triggered by an external, unprivileged action, and once triggered there is no code path back — any subsequent operation that depends on being able to move the value (restoreVault / re-spend from definer) unconditionally reverts, permanently locking funds.

### Impact Explanation
Funds (assets) sent to the definer's own address for an `auto_destroy` asset become permanently unspendable by the definer, including when the definer is an AA. If an AA's operational design does not perfectly avoid ever receiving its own `auto_destroy` asset back at its own address (a plausible design/implementation gap, since AA logic is arbitrary oscript that can be manipulated or exploited by an unprivileged trigger to force such a self-payment), the AA loses those funds forever — a concrete case of AA fund freezing, matching the required "AA fund loss or freezing" impact category. This qualifies as High severity: total, irrecoverable loss of value with no owner/emergency remedy, reachable by any ordinary unit poster who can choose payment outputs.

### Likelihood Explanation
The freezing condition activates deterministically the moment a payment output for an `auto_destroy` asset targets the definer's own address — a normal, permitted operation requiring no special privilege (`validateAADefinition`/`validatePayment` do not forbid sending to `this_address`/definer). Any AA developer using `auto_destroy` combined with a self-referential payment flow (e.g., loyalty-point recycling, buy-back-and-burn designs that also want an emergency path to reclaim tokens, or bugs where a bounce/refund accidentally routes tokens back to the AA) will hit this. It also can be intentionally triggered by an unprivileged attacker who crafts a trigger/payment that forces the AA to receive its own token at its own address, especially in flows where `trigger.address` or output addresses can be influenced or defaulted to `this_address`.

### Recommendation
Re-evaluate the `auto_destroy` semantics so that the irreversible lock cannot silently strand funds that a legitimate AA design might route back to itself:
- Explicitly document and enforce, at AA-validation time (`aa_validation.js`), that assets with `auto_destroy: true` cannot be safely used as an AA's own issued/managed asset without safeguards, or disallow AA definitions from setting themselves as `definer_address` for `auto_destroy` assets that they might also receive.
- Alternatively, treat `auto_destroy` funds sent to the definer as immediately and automatically removed from circulation at validation/write time (e.g., burn semantics enforced structurally, not just via spend rejection), rather than leaving "still-existing but permanently unspendable" balances that create ambiguous state and confusion for AA logic (e.g., balance[asset] queries in oscript may still report these frozen amounts as part of the AA balance, misleading contract logic into thinking funds are available).
- Add a way (e.g., a validated exception or dedicated `"burn"` input/message type) for confirmed intentional burns versus accidental self-payments, so the destructive effect is opt-in per-transaction rather than an unconditional address-based trap.

### Proof of Concept
1. Attacker/definer creates asset `X` with `auto_destroy: true` and `definer_address = AA_A` (an Autonomous Agent that manages/reissues asset `X`, a common oscript pattern per `test/samples/*.oscript` issuance templates).
2. Through normal AA operation (or a maliciously crafted trigger causing a bounce/refund/rebalance path), a payment message is executed that sends some amount of asset `X` to `AA_A`'s own address as an output (a completely valid `payment` message per `validatePayment`/`aa_composer.js`, no special privilege required).
3. Once that unit stabilizes, any subsequent attempt by `AA_A` (or by the original recipient) to spend that specific output of asset `X` fails validation:
   - `validation.js:2430` / `validation.js:2504`: `if (objAsset.auto_destroy && owner_address === objAsset.definer_address) return cb("this output was destroyed by sending to definer address");`
4. There is no compensating "unlock"/administrative path in `ocore` to reclaim or reissue against those specific destroyed funds — the value is permanently frozen inside `AA_A`, unusable in any future AA response, mirroring the `emergencyExit`/`restoreVault` deadlock in the reference report. [1](#0-0) [2](#0-1)

### Citations

**File:** validation.js (L2428-2432)
```javascript
						if (denomination !== src_coin.denomination)
							return cb("private denomination mismatch");
						if (objAsset.auto_destroy && owner_address === objAsset.definer_address)
							return cb("this output was destroyed by sending to definer address");
						if (objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
```

**File:** validation.js (L2502-2506)
```javascript
							if (denomination !== src_output.denomination)
								return cb("denomination mismatch");
							if (objAsset && objAsset.auto_destroy && owner_address === objAsset.definer_address)
								return cb("this output was destroyed by sending it to definer address");
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
```
