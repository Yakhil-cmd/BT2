[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** programs/system/src/system_instruction.rs (L138-151)
```rust
            } else {
                let min_balance = rent.minimum_balance(from.get_data().len());
                let amount = checked_add(lamports, min_balance)?;
                if amount > from.get_lamports() {
                    ic_msg!(
                        invoke_context,
                        "Withdraw nonce account: insufficient lamports {}, need {}",
                        from.get_lamports(),
                        amount,
                    );
                    return Err(InstructionError::InsufficientFunds);
                }
                check_signer(&data.authority)?;
            }
```

**File:** programs/system/src/system_instruction.rs (L873-903)
```rust
    #[test]
    fn withdraw_inx_initialized_acc_insuff_rent_fail() {
        prepare_mockup!(
            invoke_context,
            instruction_accounts,
            rent,
            transaction_context
        );
        push_instruction_context!(invoke_context, instruction_context, instruction_accounts);
        let mut nonce_account = instruction_context
            .try_borrow_instruction_account(NONCE_ACCOUNT_INDEX)
            .unwrap();
        set_invoke_context_blockhash!(invoke_context, 95);
        let authorized = *nonce_account.get_key();
        initialize_nonce_account(&mut nonce_account, &authorized, &rent, &invoke_context).unwrap();
        set_invoke_context_blockhash!(invoke_context, 63);
        let mut signers = HashSet::new();
        signers.insert(*nonce_account.get_key());
        let withdraw_lamports = 42 + 1;
        drop(nonce_account);
        let result = withdraw_nonce_account(
            NONCE_ACCOUNT_INDEX,
            withdraw_lamports,
            WITHDRAW_TO_ACCOUNT_INDEX,
            &rent,
            &signers,
            &invoke_context,
            &instruction_context,
        );
        assert_eq!(result, Err(InstructionError::InsufficientFunds));
    }
```
