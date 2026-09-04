[File: 'File Name: clarity/src/vm/functions/sequences.rs -> Scope: Critical.'] Target: DelegateStxOp::check (no balance validation) intersecting pox-5's get-amount-delegated-for-signer accounting used across bond rollover ('register-for-bond after old bond expires nets sBTC forward'). Attacker action: submit an over-delegated DelegateStxOp, then trigger a bond-expiry rollover (register-for-bond into a new bondIndex after the old one expires) relying on getAmountDelegatedForSigner reflecting the unbacked figure to pass the new bond's minUstxRatio gate without any fresh STX ever changing hands. Preconditions: old bond fully expired (raw protocol-bond-memberships entry still present per the known rollover edge case), new bond setup window open. Call sequence: DelegateStxOp (unbacked) -> old bond registration -> mine past old bond expiry -> new setupBond -> registerForBond rollover reusing getAmountDelegatedForSigner as authorization for the new bond's amount-ustx, again with zero real STX increase. Equality: LOCK CONSERVATION carried across a rollover — STX locked == value the staker committed and owns; an unbacked delegated_ustx figure surviving

### Citations

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L405-410)
```rust
        if self.num_cycles == 0 || self.num_cycles > POX_MAX_NUM_CYCLES {
            warn!(
