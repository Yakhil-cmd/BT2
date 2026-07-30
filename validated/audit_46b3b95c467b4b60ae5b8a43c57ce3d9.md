[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** crates/sui-core/src/signature_verifier.rs (L83-127)
```rust
impl SignatureVerifier {
    pub fn new(
        committee: Arc<Committee>,
        object_store: Arc<dyn ObjectStore + Send + Sync>,
        metrics: Arc<SignatureVerifierMetrics>,
        supported_providers: Vec<OIDCProvider>,
        zklogin_env: ZkLoginEnv,
        zklogin_circuit_mode: u64,
        verify_legacy_zklogin_address: bool,
        accept_zklogin_in_multisig: bool,
        accept_passkey_in_multisig: bool,
        zklogin_max_epoch_upper_bound_delta: Option<u64>,
        additional_multisig_checks: bool,
        validate_zklogin_public_identifier: bool,
        enable_address_aliases: bool,
    ) -> Self {
        Self {
            committee,
            object_store,
            signed_data_cache: VerifiedDigestCache::new(
                metrics.signed_data_cache_hits.clone(),
                metrics.signed_data_cache_misses.clone(),
                metrics.signed_data_cache_evictions.clone(),
            ),
            zklogin_inputs_cache: Arc::new(VerifiedDigestCache::new(
                metrics.zklogin_inputs_cache_hits.clone(),
                metrics.zklogin_inputs_cache_misses.clone(),
                metrics.zklogin_inputs_cache_evictions.clone(),
            )),
            jwks: Default::default(),
            enable_address_aliases,
            metrics,
            zk_login_params: ZkLoginParams {
                supported_providers,
                env: zklogin_env,
                zklogin_circuit_mode,
                verify_legacy_zklogin_address,
                accept_zklogin_in_multisig,
                accept_passkey_in_multisig,
                zklogin_max_epoch_upper_bound_delta,
                additional_multisig_checks,
                validate_zklogin_public_identifier,
            },
        }
    }
```

**File:** crates/sui-core/src/signature_verifier.rs (L215-251)
```rust
    fn verify_tx(
        &self,
        signed_tx: &SenderSignedData,
        alias_versions: &Vec<(SuiAddress, Option<SequenceNumber>)>,
        aliased_addresses: Vec<(SuiAddress, NonEmpty<SuiAddress>)>,
    ) -> SuiResult<Vec<u8>> {
        let digest = signed_tx.full_message_digest_with_alias_versions(alias_versions);

        if let Some(indices) = self.signed_data_cache.get_cached(&digest) {
            return Ok(indices);
        }

        let jwks = self.jwks.read().clone();
        let verify_params = VerifyParams::new(
            jwks,
            self.zk_login_params.supported_providers.clone(),
            self.zk_login_params.env,
            self.zk_login_params.zklogin_circuit_mode,
            self.zk_login_params.verify_legacy_zklogin_address,
            self.zk_login_params.accept_zklogin_in_multisig,
            self.zk_login_params.accept_passkey_in_multisig,
            self.zk_login_params.zklogin_max_epoch_upper_bound_delta,
            self.zk_login_params.additional_multisig_checks,
            self.zk_login_params.validate_zklogin_public_identifier,
        );
        let indices = verify_sender_signed_data_message_signatures(
            signed_tx,
            self.committee.epoch(),
            &verify_params,
            self.zklogin_inputs_cache.clone(),
            aliased_addresses,
        )?;

        self.signed_data_cache
            .cache_with_value(digest, indices.clone());
        Ok(indices)
    }
```
