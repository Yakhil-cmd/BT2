Found the key mechanism. `updateStorageSize` (`aa_composer.js:1531-1571`) enforces: `if (byte_balance < new_storage_size && new_storage_size > FULL_TRANSFER_INPUT_SIZE && mci >= constants.aaStorageSizeUpgradeMci) return cb("byte balance " + byte_balance + " would drop below new storage size " + new_storage_size);` This is a global, shared-resource "reserve requirement" check analogous to Rage Trade's `maxUtilizationBps` withdrawal gate: any single trigger that grows the AA's `storage_size` (by writing/enlarging state vars) permanently raises the floor that the AA's byte balance must stay above, and this floor applies to *every subsequent trigger from any user*, not just the one that caused the growth.

Given a shared-pool AA pattern like `test/samples/a_bank_without_percent.oscript`, where user withdrawals track balances in `var[balance_'||trigger.address||...]` but the actual constraint on completing a payment (`completePaymentPayload` in `aa_composer.js:1061-1138`) is against the AA's real `byte_balance` vs. `storage_size`, an attacker can post low-value deposit triggers that create many new/larger state-var keys (bumping `storage_size` up via `updateStorageSize`) while the AA's actual spendable byte balance stays low. Once `storage_size` (the "reserved" amount) approaches or exceeds the AA's real balance, subsequent legitimate withdrawal triggers from unrelated users get bounced with `"byte balance ... would drop below new storage size ..."`, even though those users' internal `var[balance_key]` accounting says they're entitled to withdraw — mirroring the utilization-based denial-of-withdrawal in the report.

However, I want to flag a caveat before finalizing: this is a plausible structural analog (global shared threshold reachable by any unprivileged trigger sender, blocking others' legitimate withdrawal), but I have not found definitive proof that `storage_size` growth alone (without an accompanying negative balance impact) is *irrecoverable* rather than a bounce-and-retry (funds aren't lost, the trigger just bounces and coins are returned per the bounce mechanism, unless bounce_fees consume them). Let me verify the finish/bounce fund-conservation semantics.Based on the investigation, I found a structural analog but could not fully verify one critical detail (semantics of `revert()` when `updateStorageSize` fails after a response unit has already been built) due to running out of iterations. I present the finding with that caveat.

### Title
AA global storage-size reserve can be inflated to permanently deny withdrawals to other users of a shared-pool AA - (File: aa_composer.js)

### Summary
`aa_composer.js`'s `updateStorageSize()` enforces a single, AA-wide "reserve" requirement (`byte_balance >= storage_size`) that any unprivileged trigger sender can permanently raise by writing/enlarging state-var keys on that AA. This mirrors the Rage Trade bug class: a shared global utilization/reserve threshold, controllable by third-party activity, that can subsequently block a legitimate, otherwise well-funded user's withdrawal.

### Finding Description
In a shared-pool AA pattern (e.g. `test/samples/a_bank_without_percent.oscript`), user funds and entitlements are tracked per-user in state vars (`var['balance_'||trigger.address||...]`), while actual spendable bytes are a single shared `byte_balance` for the whole AA. Any trigger that adds or enlarges state-var storage increases `storage_size`, a floor below which the AA's byte balance must never fall: [1](#0-0) 

Specifically, `getValueSize`-based delta is added to `storage_size`, and:
```
if (byte_balance < new_storage_size && new_storage_size > FULL_TRANSFER_INPUT_SIZE && mci >= constants.aaStorageSizeUpgradeMci)
    return cb("byte balance " + byte_balance + " would drop below new storage size " + new_storage_size);
``` [2](#0-1) 

This check is not per-user — `storage_size` is a single value stored on `aa_addresses` for the whole AA [3](#0-2) , and it never decreases unless a state var is deleted or shrunk by the same user who wrote it. Any unprivileged unit poster can send a low-value trigger to the AA whose oscript writes a large or growing number of new state-var keys (e.g. deposit/registration keys, order records, logs), driving `storage_size` up. Because `updateStorageSize` gates on the AA's *aggregate* `byte_balance` — analogous to Rage Trade's aggregate `totalUsdcBorrowed()`/`maxUtilizationBps` check — once `storage_size` approaches the AA's real byte balance, subsequent, unrelated withdrawal triggers (which pass their own internal per-user accounting check, e.g. `$required_amount <= var[$key]` in the bank sample [4](#0-3) ) fail this global reserve check and bounce with `"byte balance ... would drop below new storage size ..."`.

This directly parallels the reported bug class: a withdrawal that is legitimate by the requester's own accounting is denied because of a shared, externally-inflatable aggregate constraint (utilization in Rage Trade; `storage_size` reserve in ocore).

### Impact Explanation
If exploited against a widely-used shared-pool/bank/order-book AA, other depositors' withdrawal triggers will repeatedly bounce as long as `storage_size` exceeds the AA's byte balance, effectively freezing bytes/asset withdrawals for unrelated users of that AA until the AA's balance is topped up or the inflating vars are deleted (which, per `updateStorageSize`, only the writing address's own subsequent triggers can do). This is a fund-freezing / griefing impact reachable purely by an unprivileged unit poster sending payments/data to the AA — no special privilege required.

### Likelihood Explanation
Any AA whose oscript logic creates new state-var entries in proportion to attacker-controllable input (e.g., per-order records, per-address balance keys, logs keyed by unit hash) is affected. Given how common such patterns are in the sample AAs reviewed (`a_bank_without_percent.oscript`, `order_book_exchange.oscript`, `51_attack_game.oscript`, `fundraising_proxy.oscript`), the precondition (an AA that lets outsiders grow its persistent storage cheaply relative to its available byte balance) is realistic for real-world AA deployments, making this at least Medium/High likelihood depending on the specific AA's economics.

### Recommendation
Consider decoupling the `storage_size` reserve check from a single AA-wide `byte_balance` gate that can block unrelated operations, e.g., by charging the byte cost of new/enlarged storage directly to the triggering unit's own payment (already partly done via the "we add a change output to AA to keep balance above storage_size" logic in `completePaymentPayload` [5](#0-4) ) rather than only enforcing it as a global floor that can starve future, unrelated withdrawals. AA developers writing shared-pool oscripts should also be warned (in documentation) that storage growth is a shared, unprivileged-writable resource that must be bounded or fee-metered per user to avoid this class of griefing.

### Proof of Concept
1. Deploy a shared AA (structurally like `test/samples/a_bank_without_percent.oscript`) that on deposit stores `var['balance_'||trigger.address||'_'||asset]` and on withdrawal checks `$required_amount <= var[$key]`.
2. Attacker A repeatedly sends minimal-value triggers that create many distinct state-var keys (new addresses/assets) on the AA, each addition increasing `storage_size` per `updateStorageSize` (`aa_composer.js:1531-1567`) without depositing enough bytes to keep `byte_balance` proportionally high.
3. Once `storage_size` approaches or exceeds the AA's actual `byte_balance`, honest user B — who has a valid, sufficient `var[balance_key]` — sends a withdrawal trigger.
4. B's trigger passes the oscript-level balance check but is bounced during response finalization when `updateStorageSize` finds `byte_balance < new_storage_size` (`aa_composer.js:1564-1565`), denying B's legitimate withdrawal.

Note: I was unable to fully verify, within the remaining tool budget, whether the `revert()` path invoked on this failure (as opposed to `bounce()`) also safely returns B's incoming coins or could result in a stuck/invalid state; this would need direct examination of the `revert()` function definition in `aa_composer.js` to complete the proof of fund-safety impact beyond simple denial-of-withdrawal.

### Citations

**File:** aa_composer.js (L1077-1081)
```javascript
				// we add a change output to AA to keep balance above storage_size
				if (storage_size > FULL_TRANSFER_INPUT_SIZE && mci >= constants.aaStorageSizeUpgradeMci){
					size += OUTPUT_SIZE + (bWithKeys ? OUTPUT_KEYS_SIZE : 0);
					payload.outputs.push({ address: address, amount: storage_size });
				}
```

**File:** aa_composer.js (L1531-1565)
```javascript
	function updateStorageSize(cb) {
		if (bBouncing || trigger_opts.bAir)
			return cb();
		var delta_storage_size = 0;
		var addressVars = stateVars[address] || {};
		for (var var_name in addressVars) {
			var state = addressVars[var_name];
			if (!state.updated)
				continue;
			if (state.value === false) { // false value signals that the var should be deleted
				if (state.original_old_value !== undefined)
					delta_storage_size -= var_name.length + getValueSize(state.original_old_value);
			}
			else {
				try {
					var newSize = getValueSize(state.value);
				}
				catch (e) {
					console.log("failed to get size of new value of state var " + var_name + ": ", e);
					return cb("invalid new value of state var " + var_name);
				}
				if (newSize > constants.MAX_STATE_VAR_VALUE_LENGTH)
					return cb(`state var value too long: ${newSize}`);
				if (state.original_old_value !== undefined)
					delta_storage_size += newSize - getValueSize(state.original_old_value);
				else
					delta_storage_size += var_name.length + newSize;
			}
		}
		console.log('storage size = ' + storage_size + ' + ' + delta_storage_size + ', byte_balance = ' + byte_balance);
		var new_storage_size = storage_size + delta_storage_size;
		if (new_storage_size < 0)
			throw Error("storage size would become negative: " + new_storage_size);
		if (byte_balance < new_storage_size && new_storage_size > FULL_TRANSFER_INPUT_SIZE && mci >= constants.aaStorageSizeUpgradeMci)
			return cb("byte balance " + byte_balance + " would drop below new storage size " + new_storage_size);
```

**File:** aa_composer.js (L1568-1568)
```javascript
		conn.query("UPDATE aa_addresses SET storage_size=? WHERE address=?", [new_storage_size, address], function () {
```

**File:** test/samples/a_bank_without_percent.oscript (L5-11)
```text
				if: `{
					$key = 'balance_'||trigger.address||'_'||trigger.data.asset;
					$base_key = 'balance_'||trigger.address||'_'||'base';
					$fee = 1000;
					$required_amount = trigger.data.amount + ((trigger.data.asset == 'base') ? $fee : 0);
					trigger.data.withdraw AND trigger.data.asset AND trigger.data.amount AND $required_amount <= var[$key] AND $fee <= var[$base_key]
				}`,
```
