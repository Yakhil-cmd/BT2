# Q2941: Operational-Address Declaration address-alias edge

## Question
Can an unprivileged attacker enter through `declare_operational_address(staker_address)` when the reward address is the same as another active reward address immediately before a claim and make authorization or beneficiary selection over `eligible_operational_addresses, operational_address_to_staker_address` resolve to a stale alias, causing funds or rewards to be claimed by the wrong live participant or frozen behind a stale mapping?

## Target
- File/function: src/staking/staking.cairo::declare_operational_address
- Entrypoint: declare_operational_address(staker_address)
- Attacker controls: caller as the proposed operational address, chosen staker_address, repetition, timing around rotations
- Exploit idea: Drive the address rotation or aliasing sequence and then attempt the nearest claim, top-up, or operator-driven flow from both the old and new address perspectives.
- Invariant to test: At any point in time there should be exactly one live authorized beneficiary or operator for each reward stream and operational slot.
- Expected Immunefi impact: High - Theft of unclaimed yield
- Fast validation: Script the aliasing sequence and assert that only the intended current address can move value, and that value remains claimable after the rollover.
