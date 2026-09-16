### Title
AAs can permanently lose access to base-asset balances below the dust-input threshold when composing response payments - (File: aa_composer.js)

### Summary
`aa_composer.js`'s `sendUnit()` function, when composing an AA's outgoing payment, only picks up unspent base-asset (bytes) outputs belonging to the AA that are `>= FULL_TRANSFER_INPUT_SIZE` (defined from `TRANSFER_INPUT_SIZE`, ~60 bytes plus key-size overhead). Outputs smaller than this are silently excluded from `readStableOutputs()`/`readUnstableOutputsSentByAAs()`, the two queries used to gather spendable inputs for an AA-generated unit.

### Finding Description
In `aa_composer.js` inside `sendUnit()` → `completePaymentPayload()` → `readStableOutputs()`, the SQL filter is: [1](#0-0) 
```
WHERE address=? AND asset...IS NULL AND amount>=" + FULL_TRANSFER_INPUT_SIZE ...
```
with the accompanying comment "byte outputs less than 60 bytes (which are net negative) are ignored to prevent dust attack: spamming the AA with very small outputs so that the AA spends all its money for fees when it tries to respond" [2](#0-1) . The same filter is repeated for outputs sent by other AAs [3](#0-2) . `TRANSFER_INPUT_SIZE` is defined as a small fixed byte-accounting constant (`44+8+8`) plus optional key-size overhead [4](#0-3) , and `FULL_TRANSFER_INPUT_SIZE` derives from it (referenced throughout `iterateUnspentOutputs`) [5](#0-4) .

This design is directly analogous to `InstantManager`'s minimum-withdrawal threshold: a global, protocol-level minimum below which value becomes unusable. If an AA's balance in bytes consists exclusively (or in largest part) of small below-threshold outputs (which any user can create by sending it many tiny payments below the threshold, deliberately or accidentally, e.g. dust from failed/aborted operations, rounding remainders in `oscript` formulas, or repeated small trigger outputs), those specific coins are never selected as inputs by `sendUnit()`. Because the AA can only ever spend from outputs picked by these two queries, those specific unspent outputs remain permanently `is_spent=0` and unusable by the AA logic — the AA's on-chain byte balance shows funds that its own `balance[]`/state accounting believes are spendable, but the composer can never actually construct a unit using them. Unlike a user wallet, an AA has no manual "coin selection" escape hatch (no `minimal`/`send_all` override at the oscript level to force-include dust); it only executes what the deterministic composer logic in `sendUnit()` finds.

### Impact Explanation
This can strand real bytes belonging to an AA (and by extension its users, when the AA's payout logic depends on spending its full base balance, e.g., in `send-all` payouts, contract wind-downs, refunds, or full-balance withdrawal features implemented in `oscript`). Analogous to the `InstantManager` case, the amount is not lost from total supply, but becomes practically inaccessible through normal AA payment composition, since the composer transparently drops these outputs from consideration on every trigger execution, with no mechanism in the `oscript`/AA layer to consolidate or explicitly select dust inputs. If an oscript author writes a "withdraw all funds" (`send_all`) case, and the AA's remaining bytes balance is composed largely of dust outputs, the AA may report insufficient funds or leave a persistent unspendable residue, effectively freezing part of the AA's/users' funds — matching the "AA fund loss or freezing" acceptance criterion.

### Likelihood Explanation
Any unprivileged unit poster can trigger this by sending an AA (or another AA) a payment with base-asset outputs smaller than `FULL_TRANSFER_INPUT_SIZE` (~60 bytes) to the target AA address, at essentially zero cost relative to the amount potentially frozen if repeated. Because oscript authors commonly implement "return all funds"/`send_all` payment logic and this filter applies globally and unconditionally to all base-asset spend attempts by any AA, the condition is straightforward to hit either accidentally (as remainder amounts from formula-driven calculations) or through repeated small transfers from a griefing actor.

### Recommendation
Consider providing the AA (or the wallet/composer generally) a way to consolidate dust outputs below `FULL_TRANSFER_INPUT_SIZE` over time (e.g., a periodic system-level consolidation transaction, or allowing dust outputs to be spent together as a bundled input set whose combined value exceeds the per-input overhead, rather than filtering purely per-output amount). Alternatively, document this dust-threshold behavior explicitly to AA authors and provide oscript-level introspection of "spendable" vs "total" balance so contracts can avoid promising users access to funds that the composer can never actually spend.

### Proof of Concept
1. Attacker repeatedly sends the target AA payments of, e.g., 10–50 bytes each in the base asset (below `FULL_TRANSFER_INPUT_SIZE`, which is derived from `TRANSFER_INPUT_SIZE = 44+8+8=60` plus key-size overhead) [4](#0-3) .
2. The AA's `balance[]`/state variables (as computed by AA formula evaluation) reflect these bytes as part of the AA's total received funds.
3. When the AA later attempts to pay out via a `send_all` case or explicit withdrawal that must draw from the base asset, `sendUnit()`'s `readStableOutputs()` query excludes all these dust outputs from candidate inputs because of the `amount>=FULL_TRANSFER_INPUT_SIZE` filter [6](#0-5) .
4. The composer either fails to find enough funds ("not enough funds for X bytes") or completes the payment while leaving the dust outputs permanently unspent (`is_spent=0` forever), since no future trigger execution will pick them up either.

Note: I was unable to fully verify at what exact byte value `FULL_TRANSFER_INPUT_SIZE` resolves to (with `bWithKeys` key-size additions) since the constant's derivation continues beyond the lines retrieved; this does not affect the validity of the root cause but only the precise dust threshold in bytes.

### Citations

**File:** aa_composer.js (L37-40)
```javascript
var TRANSFER_INPUT_SIZE = 0 // type: "transfer" omitted
	+ 44 // unit
	+ 8 // message_index
	+ 8; // output_index
```

**File:** aa_composer.js (L1102-1114)
```javascript
			function iterateUnspentOutputs(rows) {
				for (var i = 0; i < rows.length; i++){
					var row = rows[i];
					var input = { unit: row.unit, message_index: row.message_index, output_index: row.output_index };
					arrUsedOutputIds.push(row.output_id);
					arrConsumedOutputs.push({asset: asset || 'base', amount: row.amount});
					payload.inputs.push(input);
					total_amount += row.amount;
					if (is_base) {
						net_target_amount += FULL_TRANSFER_INPUT_SIZE;
						size += FULL_TRANSFER_INPUT_SIZE;
						target_amount = net_target_amount + getOversizeFee(size);
					}
```

**File:** aa_composer.js (L1140-1154)
```javascript
			function readStableOutputs(handleRows) {
			//	console.log('--- readStableOutputs');
				if (asset && assetInfos[asset].auto_destroy && assetInfos[asset].definer_address === address && mci >= constants.pemCurvesFixMci)
					return handleRows([]);
				// byte outputs less than 60 bytes (which are net negative) are ignored to prevent dust attack: spamming the AA with very small outputs so that the AA spends all its money for fees when it tries to respond
				conn.query(
					"SELECT unit, message_index, output_index, amount, output_id \n\
					FROM outputs \n\
					CROSS JOIN units USING(unit) \n\
					WHERE address=? AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>=" + FULL_TRANSFER_INPUT_SIZE)+" AND is_spent=0 \n\
						AND sequence='good' AND main_chain_index<=? \n\
						AND output_id NOT IN("+(arrUsedOutputIds.length === 0 ? "-1" : arrUsedOutputIds.join(', '))+") \n\
					ORDER BY main_chain_index, unit, output_index", // sort order must be deterministic
					[address, mci], handleRows
				);
```

**File:** aa_composer.js (L1157-1173)
```javascript
			function readUnstableOutputsSentByAAs(handleRows) {
			//	console.log('--- readUnstableOutputsSentByAAs');
				if (asset && assetInfos[asset].auto_destroy && assetInfos[asset].definer_address === address && mci >= constants.pemCurvesFixMci)
					return handleRows([]);
				conn.query(
					"SELECT outputs.unit, message_index, output_index, amount, output_id \n\
					FROM outputs \n\
					CROSS JOIN units USING(unit) \n\
					CROSS JOIN unit_authors USING(unit) \n\
					CROSS JOIN aa_addresses ON unit_authors.address=aa_addresses.address \n\
					WHERE outputs.address=? AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>="+FULL_TRANSFER_INPUT_SIZE)+" AND is_spent=0 \n\
						AND sequence='good' AND (main_chain_index>? OR main_chain_index IS NULL) \n\
						AND output_id NOT IN("+(arrUsedOutputIds.length === 0 ? "-1" : arrUsedOutputIds.join(', '))+") \n\
					ORDER BY latest_included_mc_index, level, outputs.unit, output_index", // sort order must be deterministic
					[address, mci], handleRows
				);
			}
```
