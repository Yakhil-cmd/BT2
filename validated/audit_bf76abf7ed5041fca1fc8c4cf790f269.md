[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L726-741)
```text
        ;; An existing STX-only stake is allowed only if its term ends no
        ;; later than this bond's first reward cycle (no overlap). A stx-only
        ;; stake has no L1 collateral, so there's no L1-unlock-window gate
        ;; here -- the lock just extends forward via the node-side handler.
        (asserts!
            (match existing-stake
                stake-info (<=
                    (+ (get first-reward-cycle stake-info)
                        (get num-cycles stake-info)
                    )
                    first-reward-cycle
                )
                true
            )
            ERR_ALREADY_STAKED
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L764-770)
```text
        ;; Reject if an existing membership *overlaps* this bond. An existing
        ;; bond whose staking term ends no later than this bond's first cycle
        ;; (e.g. rolling from bond N into bond N+6) is allowed.
        (asserts!
            (not (bond-overlaps-new-position? existing-membership first-reward-cycle))
            ERR_ALREADY_REGISTERED
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1679-1690)
```text
            ;; Get the total uSTX delegated (through protocol bonds and STX-only
            ;; staking) to this signer.
            (cur-delegated-for-signer (get-amount-delegated-for-signer signer cycle))
            (amount (get amount-ustx accumulator))
            (stake-amount (if (get is-stx-staking accumulator)
                amount
                u0
            ))
            (staker (get staker accumulator))
            (prev-staked (get-signer-pending-staked-ustx-per-cycle signer cycle))
            (prev-total-shares-staked (get-total-shares-staked-for-cycle cycle none))
            (new-delegated (+ cur-delegated-for-signer amount))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1705-1724)
```text
        (if (>= new-delegated SIGNER_SET_MIN_USTX)
            (begin
                (map-set signer-shares-staked-for-cycle {
                    reward-cycle: cycle,
                    bond-index: none,
                    signer: signer,
                }
                    (+ prev-staked stake-amount)
                )
                (if (< cur-delegated-for-signer SIGNER_SET_MIN_USTX)
                    ;; They just crossed the threshold - add to signer set and add to reward calculations
                    (begin
                        (add-signer-to-set-for-cycle signer cycle)
                        (map-set total-shares-staked-for-cycle {
                            reward-cycle: cycle,
                            bond-index: none,
                        }
                            (+ prev-total-shares-staked prev-staked stake-amount)
                        )
                    )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L3436-3444)
```text
(define-read-only (signer-set-contains-for-cycle
        (signer principal)
        (cycle uint)
    )
    (is-some (map-get? signer-set-ll-for-cycle {
        cycle: cycle,
        signer: signer,
    }))
)
```

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L424-447)
```rust
        // Total uSTX delegated to this signer for this cycle (sums STX-only
        // staking and protocol bonds; see signer-delegated-per-cycle).
        let amount_ustx = self
            .clarity
            .eval_method_read_only(
                &self.pox_contract,
                "get-amount-delegated-for-signer",
                &[lookup_signer.clone(), self.reward_cycle_clar.clone()],
            )
            .map_err(|e| PoxEntryParsingError::Skip(e.to_string()))?
            .expect_u128()
            .map_err(|_| {
                PoxEntryParsingError::Skip(
                    "get-amount-delegated-for-signer did not return uint".into(),
                )
            })?;

        // Signers only enter the linked list after crossing SIGNER_SET_MIN_USTX,
        // so a zero here means contract state is inconsistent. Skip defensively.
        if amount_ustx == 0 {
            return Err(PoxEntryParsingError::Skip(format!(
                "signer {cur_signer} is in cycle linked list with zero delegated uSTX"
            )));
        }
```
