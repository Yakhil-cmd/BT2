### Title
Griefer can pre-fund a not-yet-defined AA-defined-AA (factory-created child AA) address to corrupt its assumed initial balance/state - ([File: storage.js])

### Summary
Autonomous Agents can programmatically create other AAs ("AA-defined AAs"), typically used to implement factory patterns (e.g. a DEX AA that spawns a per-pair pool AA with a deterministic address). The child AA's address is `chash160(definition)`, which is fully computable off-chain by anyone before the factory ever fires, exactly like a TraderJoe pair address computed from `token0`/`token1`. Because `storage.insertAADefinitions()` retroactively sweeps *all* prior good outputs sent to that address into `aa_balances` once the definition finally activates, an attacker can pre-send funds to the still-unclaimed address before the factory's trigger runs, silently corrupting the balance the child AA will see as its "genesis" funding — an analog of the JoePair front-running/squatting griefing vector, but expressed through balance corruption instead of a revert-based DoS.

### Finding Description
A factory AA computes a child AA's address deterministically and, in the same response, both posts the `definition` message and sends it a payment, expecting the child AA's first-ever balance to equal exactly what it deposits: [1](#0-0) 

The address is `chash160($child_aa)`, and — as in the TraderJoe pair case — is knowable by anyone who can reproduce the deterministic template (fixed template, or `base_aa`+`params` derived from public data such as asset identifiers) before the factory transaction is even sent. Nothing in unit or `definition` message validation restricts who may send ordinary payments to that address in the meantime: [2](#0-1) 

When the definition finally activates, `insertAADefinitions()` computes the AA's opening balance by summing **all previously received, unspent, good-sequence outputs** sent to that address with `main_chain_index` below the activation mci (or flagged `is_aa_response`), not just the funds sent by the defining unit itself: [3](#0-2) 

Because the address had no known definition before this point, it behaved as an ordinary, uncontrolled address that anyone could pay into; those funds get folded into `aa_balances` unconditionally, with no mechanism for the defining factory to detect or reject "unexpected" pre-existing balance (unlike, say, a check that the sole output was the factory's own payment).

### Impact Explanation
Any AA design that infers "initial reserves", "initial price", or a "1:1 minted-share ratio" from the first-observed balance of a freshly created child AA (a very common oscript pattern for AMM/pool factories, vesting AAs, or per-user vault AAs with deterministic/predictable addresses) is exposed. An attacker who can predict the child AA address ahead of time can seed it with an arbitrary, disproportionate amount of one asset before the factory's defining trigger lands, permanently skewing the pool's/vault's assumed opening state. This can lead to loss of funds for depositors relying on the intended initial ratio/state, or to unusable/frozen contract state if the child AA's logic asserts an invariant on its own balance that the injected funds violate — the same class of impact (fund loss / permanent freezing of a reachable, fund-holding flow) flagged Medium/High in the original TraderJoe report, achieved here purely through a normal payment unit rather than a privileged action.

### Likelihood Explanation
Exploitability requires only that: (1) the attacker can derive the future child-AA address off-chain (straightforward whenever the factory AA's child template/params are public or inferable, as demonstrated in the codebase's own factory-pattern tests), and (2) the attacker sends an ordinary payment before the factory's trigger executes — no special privilege, node, or timing beyond normal unit posting is needed. Likelihood is therefore driven entirely by AA-author design choices (whether the child AA trusts its "first balance" as ground truth), which is common in factory/AMM-style contracts built on this platform.

### Recommendation
- Do not let an AA-defined AA implicitly inherit balances that were sent to its address *before* its `definition` was posted; either exclude pre-existing balance from `aa_balances` on activation, or expose it separately (e.g. as a distinguishable "unexpected_balance" bucket) so AA authors can detect and refund/ignore it.
- Alternatively, document prominently (and enforce via `aa_validation.js`) that factory-created child AAs must explicitly read `trigger.output` for the specific defining payment rather than relying on aggregate `balance[...]`, and provide a getter/state var indicating how much of the current balance predates the defining unit.
- Consider making the balance sweep in `storage.js`'s `insertAADefinitions()` (lines 944-962) configurable/off by default for factory-defined AAs, matching the “only the defining actor should be able to establish genesis state” principle recommended in the original TraderJoe report.

### Proof of Concept
1. A factory AA, when triggered, deterministically computes a child AA definition (fixed template or `base_aa`+`params` built from public inputs) exactly as shown in the existing test pattern: [4](#0-3) 
2. Before the factory's trigger is sent/confirmed, an attacker (any unprivileged unit poster) computes `child_aa_address = chash160(child_aa_definition)` off-chain and sends a plain payment with a disproportionate amount of one asset to that address.
3. When the factory later fires and posts the `definition` message for `child_aa_address`, `storage.insertAADefinitions()` sweeps in *all* qualifying prior outputs (including the attacker's) into `aa_balances`: [5](#0-4) 
4. The child AA's first trigger execution now observes a balance that includes the attacker's pre-seeded funds in addition to (or instead of) the factory's intended deposit, corrupting any logic that assumes the balance equals only the just-received trigger payment.

### Citations

**File:** test/aa_composer.test.js (L944-985)
```javascript
	var factory_aa = ['autonomous agent', {
		init: `{
			$child_aa = ['autonomous agent', {
				bounce_fees: { base: 10000 },
				doc_url: 'https://myapp.com/description.json',
				messages: [
					{
						app: 'payment',
						payload: {
							asset: 'base',
							init: "{response['received_amount'] = trigger.output[[asset=base]];}",
							outputs: [
								{address: "{trigger.initial_address}", amount: "{min(trigger.output[[asset=base]] - 2000, 5000)}"}
							]
						}
					}
				]
			}];
			$child_aa_address = chash160($child_aa);
		}`,
		messages: [
			{
				app: 'definition',
				payload: {
					definition: `{$child_aa}`
				}
			},
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [{address: `{$child_aa_address}`, amount: 8000}]
				}
			},
			{
				app: 'state',
				state: `{
					var['child_aa1'] = $child_aa_address;
					var['child_aa2'] = unit[response_unit].messages[[.app='definition']].payload.address;
				}`
			}
		]
```

**File:** validation.js (L1747-1761)
```javascript
		case "definition": // for AAs only
			if (!isNonemptyObject(payload))
				return callback("payload must be a non empty object");
			if (hasFieldsExcept(payload, ["address", "definition"])) // AA definition cannot be changed and its address is also its definition_chash
				return callback("unknown fields in app definition");
			try{
				if (payload.address !== objectHash.getChash160(payload.definition))
					return callback("definition doesn't match the chash");
			}
			catch(e){
				return callback("bad definition");
			}
			if (constants.bTestnet && ['BD7RTYgniYtyCX0t/a/mmAAZEiK/ZhTvInCMCPG5B1k=', 'EHEkkpiLVTkBHkn8NhzZG/o4IphnrmhRGxp4uQdEkco=', 'bx8VlbNQm2WA2ruIhx04zMrlpQq3EChK6o3k5OXJ130=', '08t8w/xuHcsKlMpPWajzzadmMGv+S4AoeV/QL1F3kBM=', '4N5fsU9qJSn2FuS70cChKx8QqgcesPRPs0dNfzOhoXw='].indexOf(objUnit.unit) >= 0)
				return callback();
			const top_mci = objValidationState.aa_mci || objValidationState.last_ball_mci;
```

**File:** storage.js (L944-962)
```javascript
					var verb = bAlreadyPostedByUnconfirmedAA ? "REPLACE" : "INSERT";
					// pre-fix, the defining AA unit's own outputs are already in the outputs table and would be double-counted with its secondary trigger
					const or_sent_by_aa = (bAlreadyPostedByUnconfirmedAA || mci >= constants.pemCurvesFixMci) ? "OR is_aa_response=1" : "";
					// for AA-defined AAs, mci is the trigger mci whose triggers were already selected before this AA existed, so outputs on this mci can never trigger it and must be counted here.
					// Also count payments from other AA responses (never primary triggers) except the defining unit's own, which arrives as a secondary trigger
					const bImmediatelyVisible = bForAAsOnly && mci >= constants.pemCurvesFixMci;
					const mci_cond = bImmediatelyVisible
						? "(main_chain_index<=? OR is_aa_response=1) AND outputs.unit!=?"
						: "(main_chain_index<? " + or_sent_by_aa + ")"; // "<" for regular AAs, not including the outputs on the current mci, which will trigger the AA and be accounted for separately; is_aa_response=1 captures outputs to the not-yet-AA by AA responses
					const params = bImmediatelyVisible ? [address, mci, unit] : [address, mci];
					conn.query(
						verb + " INTO aa_balances (address, asset, balance) \n\
						SELECT address, IFNULL(asset, 'base'), SUM(CAST(amount AS DOUBLE)) AS balance \n\
						FROM outputs \n\
						CROSS JOIN units USING(unit) \n\
						LEFT JOIN assets ON asset=assets.unit \n\
						WHERE address=? AND is_spent=0 AND sequence='good' AND " + mci_cond + " AND (is_private=0 OR is_private IS NULL) \n\
						GROUP BY address, asset",
						params,
```
