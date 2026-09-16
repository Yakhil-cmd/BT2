This confirms the analog. The `register` case in this sample AA registers any `$id` (which could represent a name, NFT ID, or arbitrary identifier) permanently to `trigger.address` with no fee requirement and no ownership/whitelist check — `var['owner_' || $id]` is set unconditionally to whoever's trigger unit reaches the AA first, exactly matching the `vestFor` bug class: any unprivileged caller can front-run a legitimate registration for a target `$id` using a dust-amount trigger, permanently and irrevocably blocking the rightful owner (since there's no update path once `owner_<id>` is set) [1](#0-0) .

### Title
Unrestricted "register" trigger in things-registry AA permanently front-runs and locks out legitimate owners - (File: test/samples/things_registry_and_marketplace.oscript)

### Summary
The `things_registry_and_marketplace.oscript` autonomous-agent template accepts a `register` trigger from any address for any caller-chosen `$id` (`trigger.data.id`), and unconditionally assigns ownership of that `id` to `trigger.address` if `var['owner_' || $id]` is not yet set, with no whitelist, no fee proportional to value, and no way to reassign or dispute ownership afterward.

### Finding Description
In the `register` case, the guard is simply `if (var['owner_' || $id]) bounce('thing ' || $id || ' already registered');` — the very first unit that reaches the AA with a given `$id` claims permanent ownership via `var['owner_' || $id] = trigger.address;` [1](#0-0) . There is no authentication tying `$id` to any prior claim, deposit proportional to the value of the registered "thing," reservation/commit-reveal scheme, or any recovery path if the wrong address wins the race. Since AA triggers are just ordinary payment units sent to the AA's address, and any unprivileged unit poster can construct and post such a trigger, an attacker who observes (or predicts) a pending legitimate `register` request for a specific `$id` can post a competing trigger with a smaller `trigger.output[[asset=base]]` payment (only the bounce-fee minimum is required, since there's no `$price`/fee validation for `register` itself) and, if it lands first or in the same batch with lower ordering, permanently squats the `id`. This mirrors the `vestFor` bug class: an unauthenticated function operates on a caller-supplied "target" key on behalf of whichever caller reaches it first, with irreversible state and no post-hoc correction, enabling griefing/DoS of the legitimate party and hijacking of a scarce on-chain resource (the registered "thing"/NFT-like identifier).

### Impact Explanation
Once squatted, the legitimate registrant permanently loses the ability to register their own thing under `$id` — the AA state var `owner_<id>` never resets and there's no override path in the template. If `$id` corresponds to a valuable name, or the "thing" being registered has real-world value (as the template explicitly is designed for names/NFTs/physical-object identifiers), this directly causes fund/asset loss or denial of legitimate registration — a form of front-running griefing DoS reachable by any AA trigger sender with a trivial amount of bytes, consistent with "AA fund loss or freezing" in scope.

### Likelihood Explanation
Likelihood is high: triggering the AA only requires posting a standard payment+data unit to a known AA address, which is exactly the guaranteed-reachable "unprivileged AA trigger sender" surface. No special permissions, keys, or race with high fees are needed — an attacker only needs to observe or guess a target `$id` before the legitimate user's registration unit stabilizes, and the AA imposes no cost scaling with the value of the id being registered.

### Recommendation
Require a commit-reveal scheme (e.g., first commit a hash of `$id` plus a secret, then reveal after a delay) or require the registrant to already control/prove some external claim to `$id` (e.g., via attestation or a `has_definition_change`/`attested` proof), and/or require a registration deposit large enough to disincentivize squatting, with a dispute/refund mechanism. At minimum, document that `register` is a race and should not be relied upon for anything of value without an off-chain reservation step guaranteeing exclusivity before broadcasting the `register` trigger.

### Proof of Concept
1. Alice wants to register `id = "alice-brand"` and broadcasts a trigger unit `{data: {register: true, id: "alice-brand"}}` paying the AA's minimum bounce fee.
2. Attacker Mallory observes Alice's pending (unstable) unit in the DAG/mempool-equivalent, and immediately posts her own trigger `{data: {register: true, id: "alice-brand"}}` with a unit that gets included/stabilized first (e.g., by using a lower-latency node or better fee/parent selection).
3. When both units are processed, whichever reaches the AA first executes `var['owner_alice-brand'] = trigger.address` and sets it to Mallory's address; the state-var check `if (var['owner_' || $id])` in the `if:` case ordering then causes Alice's later-processed trigger to hit the `bounce('thing alice-brand already registered')` branch permanently [2](#0-1) .
4. Alice can never register `"alice-brand"` under this AA again; there is no dispute or override mechanism in the template.

### Citations

**File:** test/samples/things_registry_and_marketplace.oscript (L22-43)
```text
			{ // register a new thing and optionally put it on sale
				if: `{trigger.data.register AND $id}`,
				init: `{
					if (var['owner_' || $id])
						bounce('thing ' || $id || ' already registered');
					if (trigger.data.sell){
						$price = trigger.data.price;
						if (!$price || !($price > 0) || round($price) != $price)
							bounce('please set a positive integer price');
					}
				}`,
				messages: [
					{
						app: 'state',
						state: `{
							var['owner_' || $id] = trigger.address;
							if (trigger.data.sell AND trigger.data.price)
								var['price_' || $id] = trigger.data.price;
							response['message'] = 'registered' || (trigger.data.sell AND trigger.data.price ? ' and put on sale for ' || trigger.data.price : '');
						}`
					}
				]
```
