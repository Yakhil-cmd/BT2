No vulnerability found for this question.

**Analysis:**

The `on_new_epoch` function in `epoch_timeout_config.move` is declared `public(friend)`, restricted to `aptos_framework::reconfiguration_with_dkg` — it cannot be invoked directly by an unprivileged transaction sender at all. [1](#0-0) [2](#0-1) 

Even setting aside the visibility restriction, the underlying `config_buffer::extract_v2` removes the entry from the `SimpleMap` via `configs.configs.remove(&key)`, so `does_exist` correctly returns `false` immediately after extraction — there is no double-consumption path within or across calls. [3](#0-2)  Calling `on_new_epoch` a second time in the same cycle is a documented no-op guarded by `config_buffer::does_exist`, exactly as the hypothesis suggests should happen, and this is confirmed by the framework's own test `init_buffer_apply`. [4](#0-3) [5](#0-4) 

This code has no connection to transaction admission — sender, signer set, sequence number, chain-id, expiry, or domain binding are not touched anywhere in this module, nor is there any entrypoint reachable from mempool, vm-validator, or an unprivileged transaction/authenticator/API path. This falls entirely outside the required admission-boundary scope.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/epoch_timeout_config.move (L14-14)
```text
    friend aptos_framework::reconfiguration_with_dkg;
```

**File:** aptos-move/framework/aptos-framework/sources/configs/epoch_timeout_config.move (L41-42)
```text
    public(friend) fun on_new_epoch(framework: &signer) acquires EpochTimeoutConfig {
        system_addresses::assert_aptos_framework(framework);
```

**File:** aptos-move/framework/aptos-framework/sources/configs/epoch_timeout_config.move (L43-50)
```text
        if (config_buffer::does_exist<EpochTimeoutConfig>()) {
            let new_config = config_buffer::extract_v2<EpochTimeoutConfig>();
            if (exists<EpochTimeoutConfig>(@aptos_framework)) {
                *borrow_global_mut<EpochTimeoutConfig>(@aptos_framework) = new_config;
            } else {
                move_to(framework, new_config);
            }
        }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/epoch_timeout_config.move (L87-101)
```text
    #[test(framework = @0x1)]
    fun init_buffer_apply(framework: signer) acquires EpochTimeoutConfig {
        initialize_for_testing(&framework);
        assert!(force_end_grace_period_secs().is_none(), 1);

        set_for_next_epoch(&framework, new_with_grace_period(30));
        on_new_epoch(&framework);
        let gp = force_end_grace_period_secs();
        assert!(gp.is_some(), 2);
        assert!(*gp.borrow() == 30, 3);

        set_for_next_epoch(&framework, new_disabled());
        on_new_epoch(&framework);
        assert!(force_end_grace_period_secs().is_none(), 4);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/config_buffer.move (L86-91)
```text
    public(friend) fun extract_v2<T: store>(): T acquires PendingConfigs {
        let configs = borrow_global_mut<PendingConfigs>(@aptos_framework);
        let key = type_info::type_name<T>();
        let (_, value_packed) = configs.configs.remove(&key);
        value_packed.unpack()
    }
```
