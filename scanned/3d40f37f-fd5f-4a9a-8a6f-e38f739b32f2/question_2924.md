# Q2924: Operational-Address Rotation address-alias edge

## Question
Can an unprivileged attacker enter through `change_operational_address(operational_address)` when the reward address is the same as another active reward address after a reward-address change but before the next update and make authorization or beneficiary selection over `eligible_operational_addresses, operational_address_to_staker_address, staker_info.operational_address` resolve to a stale alias, causing funds or rewards to be claimed by the wrong live participant or frozen behind a stale mapping?

## Target
- File/function: src/staking/staking.cairo::change_operational_address
- Entrypoint: change_operational_address(operational_address)
- Attacker controls: caller, declared operational_address, timing relative to old and new operator use
- Exploit idea: Drive the address rotation or aliasing sequence and then attempt the nearest claim, top-up, or operator-driven flow from both the old and new address perspectives.
- Invariant to test: At any point in time there should be exactly one live authorized beneficiary or operator for each reward stream and operational slot.
- Expected Immunefi impact: High - Theft of unclaimed yield
- Fast validation: Script the aliasing sequence and assert that only the intended current address can move value, and that value remains claimable after the rollover.
