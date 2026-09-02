### Title
Webhook signature is verified against an attacker-chosen organization while handlers act on an independent repository field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to check the HMAC signature against by reading `repository_owner` out of the **unverified** JSON body, then verifies the signature with that org's secret. Once verification passes, the whole (still attacker-supplied) `params` hash — including the `repository.full_name` field that downstream handlers key on — is dispatched to `Shipit::Webhooks.for_event(event)` handlers. The field used to *select the signing key* (`repository.owner.login` / `organization.login`) and the field the handlers actually *act on* (`repository.full_name`, commit `sha`, `branches`, etc.) are never checked for consistency, breaking the intended binding `verified_organization == acted_upon_repository`.

### Finding Description
`verify_signature` computes the organization to verify against purely from payload content: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up the `webhook_secret` configured for whatever organization name appears in the (still-unverified) body, and `verify_webhook_signature` HMACs the *raw body* against that secret: [3](#0-2) 

After the signature check passes, the raw, attacker-controlled `params` hash (not just the `repository_owner`) is forwarded unchanged to every registered handler for the event: [4](#0-3) 

This mirrors the Timeswap bug class exactly: the signature (analogous to the `pool.long0FeeGrowth`/`shortFeeGrowth` state used at mint time) is computed/verified against one derived value (`repository_owner`), while the state that is actually mutated downstream (repository/stack matched by `repository.full_name`, commit `sha`, branch, etc., analogous to the LP's stale `growth`/`fee` fields) is a *different* field of the same payload that was never bound to that verification. Nothing forces `repository.owner.login` used for key selection to equal the owner embedded in `repository.full_name` used by handlers such as the push handler (`GithubSyncJob`) or the `status`/`membership` handlers seen in the test fixtures.

### Impact Explanation
An attacker who legitimately controls a repository under Organization A (and therefore genuinely knows/can register Org A's `webhook_secret`, e.g. by being a collaborator with webhook-admin rights on one of Org A's repos) can sign a payload with Org A's secret while setting `repository.full_name` (or `organization.login` fallback) to point at Organization B / a different stack entirely. Because handlers trust the full unverified payload once the signature "passes," this can drive state changes (e.g. `GithubSyncJob` enqueued with a forged `stack_id`/sha, spoofed commit statuses, or `membership`/`Team`/`User` creation as in the `:membership` handler tests) against a stack/org the attacker does not otherwise control — i.e., cross-repository writes without needing that repository's own secret.

### Likelihood Explanation
Exploitability depends entirely on the attacker being able to obtain *some* organization's legitimate `webhook_secret` (e.g., their own org configured in Shipit) and is bounded by which Shipit event handlers trust repository-identifying fields without independently confirming they match the organization the signature was verified under. This is a real code-level binding gap in `WebhooksController`, not a hypothetical deployment misconfiguration, but its severity is capped by needing a genuine (if unrelated) webhook secret.

### Recommendation
After signature verification, re-derive the target stack/repository strictly from the same `repository_owner`/organization value used for signature verification, and reject payloads whose `repository.full_name`/`organization.login` do not match the organization whose secret validated the signature.

### Proof of Concept
1. Attacker sets up an organization "AttackerOrg" in Shipit's github config with a known `webhook_secret`.
2. Attacker crafts a `push` payload: `{"repository": {"owner": {"login": "AttackerOrg"}, "full_name": "victim-org/victim-repo"}, "after": "<forged sha>"}`.
3. Attacker computes `X-Hub-Signature` using AttackerOrg's `webhook_secret` over the raw body.
4. `verify_signature` calls `Shipit.github(organization: "AttackerOrg")` and successfully verifies the signature against the crafted body.
5. `create` dispatches the full payload (with `repository.full_name = "victim-org/victim-repo"`) to the push handler, which looks up/acts on the `victim-org/victim-repo` stack using attacker-controlled `after` sha, despite the signature never having been validated against victim-org's secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
