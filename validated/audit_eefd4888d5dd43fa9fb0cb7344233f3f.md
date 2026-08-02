No vulnerability found for this question.

**Reasoning:** The scenario described is not applicable to the transaction-admission boundary defined in the review scope, and the code itself does not exhibit the described flaw.

`ensure_paired_metadata<CoinType>()` calls `create_and_return_paired_metadata_if_not_exist<CoinType>` which keys the `CoinConversionMap.coin_to_fungible_asset_map` table by `type_info::type_of<CoinType>()` — the actual, VM-resolved concrete type substituted for the generic parameter [1](#0-0) . An unprivileged caller supplying `CoinType = A` in an entry function can never cause the Move VM to resolve `type_of<A>()` to anything other than `A`'s own `TypeInfo`; there is no mechanism in this module (or in Move's generics/type system generally) for a type argument to alias to a different type's identity. This makes the map lookup deterministic and 1:1 per concrete type, so `coin_to_fungible_asset<A>` can only ever look up (or lazily create) `A`'s own paired `Metadata` object, never `B`'s [2](#0-1) .

Additionally, the reverse direction `fungible_asset_to_coin<CoinType>` explicitly re-checks the binding by reading the `PairedCoinType.type` stored at the metadata object's address and asserting it equals `type_info::type_of<CoinType>()`, aborting with `ECOIN_TYPE_MISMATCH` otherwise [3](#0-2) . This is a redundant, defense-in-depth check confirming the coin↔metadata pairing is bijective and enforced, not merely assumed.

Even setting aside the code's correctness, this logic lives entirely inside `aptos-framework/sources/coin.move`, a Move module executing under normal VM type-generic semantics — it is not part of the authenticator, mempool, vm-validator, or any sender/signer/sequence/chain-id/replay binding path that the admission review scope covers [4](#0-3) . No unprivileged transaction-admission guarantee (sender, signer set, fee payer, replay, sequence, expiry, chain-id, or domain binding) is implicated by generic type-argument resolution inside a Move module's internal table keyed by intrinsic `TypeInfo`.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L330-331)
```text
        let type = type_info::type_of<CoinType>();
        if (!map.coin_to_fungible_asset_map.contains(type)) {
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L337-363)
```text
            let metadata_object_cref =
                if (is_apt) {
                    object::create_sticky_object_at_address(
                        @aptos_framework, @aptos_fungible_asset
                    )
                } else {
                    object::create_named_object(
                        &create_signer::create_signer(@aptos_fungible_asset),
                        *type_info::type_name<CoinType>().bytes()
                    )
                };
            primary_fungible_store::create_primary_store_enabled_fungible_asset(
                &metadata_object_cref,
                option::none(),
                name<CoinType>(),
                symbol<CoinType>(),
                decimals<CoinType>(),
                string::utf8(b""),
                string::utf8(b"")
            );

            let metadata_object_signer = &metadata_object_cref.generate_signer();
            let type = type_info::type_of<CoinType>();
            move_to(metadata_object_signer, PairedCoinType { type });
            let metadata_obj = metadata_object_cref.object_from_constructor_ref();

            map.coin_to_fungible_asset_map.add(type, metadata_obj);
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L404-411)
```text
    /// Conversion from coin to fungible asset
    public fun coin_to_fungible_asset<CoinType>(
        coin: Coin<CoinType>
    ): FungibleAsset acquires CoinConversionMap, CoinInfo {
        let metadata = ensure_paired_metadata<CoinType>();
        let amount = burn_internal(coin);
        fungible_asset::mint_internal(metadata, amount)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L413-429)
```text
    /// Conversion from fungible asset to coin. Not public to push the migration to FA.
    fun fungible_asset_to_coin<CoinType>(
        fungible_asset: FungibleAsset
    ): Coin<CoinType> acquires CoinInfo, PairedCoinType {
        let metadata_addr =
            fungible_asset.asset_metadata().object_address();
        assert!(
            object::object_exists<PairedCoinType>(metadata_addr),
            error::not_found(EPAIRED_COIN)
        );
        let coin_type_info = borrow_global<PairedCoinType>(metadata_addr).type;
        assert!(
            coin_type_info == type_info::type_of<CoinType>(),
            error::invalid_argument(ECOIN_TYPE_MISMATCH)
        );
        let amount = fungible_asset.burn_internal();
        mint_internal<CoinType>(amount)
```
