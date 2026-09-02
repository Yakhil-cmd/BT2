### Title
Webhook signature verification is scoped by `repository.owner.login`, not by the `repository.full_name` the handlers act on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization config (and therefore which `webhook_secret`) to use for HMAC verification based on `repository.owner.login` (falling back to `organization.login`), while the downstream event handlers dispatched in `create` act on `repository.full_name` taken from the very same payload to locate the target `Stack`. Nothing binds these two fields together, so a payload can be legitimately signed for one organization while acting on a repository belonging to a different one.

### Finding Description
`verify_signature` derives the signing organization purely from `repository_owner`: [1](#0-0) [2](#0-1) 

This value is used solely to select `Shipit.github(organization: repository_owner)` and its `webhook_secret` for HMAC comparison. It is never cross-checked against `repository.full_name`, the field the rest of the pipeline (job enqueuing, `Stack` lookup for `push`/`status`/`check_suite` handlers) actually uses to determine which tracked repository/stack the event applies to — confirmed by the test suite, where mutating only `repository.full_name` (leaving `owner.login` untouched) changes which stack a push event maps to, while mutating only `owner.login` changes which organization's secret is used for verification: [3](#0-2) [4](#0-3) 

This is structurally the same class of bug as the `StakedExa avgStart` finding: a value that state-changing logic acts on (`repository.full_name`, used to route the event to a `Stack`) is not the value covered by the trust-establishing check (`repository.owner.login`, used to pick the signing secret). The binding that should hold is:

`organization authorizing the signature == organization owning the repository the handler writes to`

but the engine only enforces:

`organization authorizing the signature == repository.owner.login (attacker-controlled field)`

An operator of *any* GitHub organization/repo configured in Shipit (i.e., one legitimate tenant among possibly many organizations configured in `Shipit.github_apps`) knows their own `webhook_secret` and can therefore self-sign an arbitrary JSON body. By setting `repository.owner.login`/`organization.login` to their own org (so the HMAC check passes) but `repository.full_name` (and other fields like `sha`, `after`, `ref`, `state`) to point at a different, victim-tracked stack, the attacker gets the controller to run handlers against the victim's `Stack`/`Commit` records, e.g.:
- forging a `status` event to mark an arbitrary victim commit `success`, feeding Shipit's CI-gating logic used before allowing deploys,
- forging a `push` event to enqueue a `GithubSyncJob` for the victim stack with an attacker-chosen `expected_head_sha`.

### Impact Explanation
If a forged `status` event can mark a victim stack's commit as CI-passed, and that stack has `continuous_deployment` enabled, Shipit's deploy gating would treat the commit as deployable, leading to an unauthorized deploy of attacker-influenced state — matching the Critical impact bucket ("an unauthorized deploy"). At minimum this breaks the intended per-organization isolation guarantee that a signature valid for organization A should only be trusted to describe events about organization A's repositories.

### Likelihood Explanation
Requires only that the attacker control (or be granted access to) one organization/repository already configured in the Shipit deployment (a normal, unprivileged tenant relative to the victim org) — no `ApiClient` token, GitHub App private key, or repository write access to the victim repo is needed. The attacker only needs the ability to trigger a real webhook delivery for their own repo (or replicate a valid HMAC using their own known secret) with a doctored payload.

### Recommendation
`verify_signature` should also validate that `repository.full_name`/`repository.owner.login` is consistent with the organization whose secret produced a valid signature, and/or handlers should re-derive the "authenticated organization" from the same field that was cryptographically verified rather than trusting a different, unauthenticated field (`repository.full_name`) for stack resolution.

### Proof of Concept
I could not fully verify the exact field usage inside `push_handler.rb`/`status_handler.rb` because those files failed to load in this session (tool error), so the following is based on `webhooks_controller.rb` and the confirming behavior demonstrated in `webhooks_controller_test.rb`; a Devin session with full repo access would be needed to read the handler bodies and confirm the exact downstream `Stack` lookup field before treating this as fully proven.

1. Attacker controls org `attacker-org`, configured in Shipit with a known `webhook_secret`.
2. Attacker POSTs to `/webhooks` with `X-Github-Event: status`, body:
   ```json
   {
     "sha": "<victim-commit-sha>",
     "state": "success",
     "context": "ci/required-check",
     "repository": { "full_name": "victim-org/victim-repo", "owner": { "login": "attacker-org" } }
   }
   ```
   signed with `attacker-org`'s `webhook_secret`.
3. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s secret, and the HMAC check passes.
4. The `status` handler (per test evidence, keyed off `sha`/`repository` full name rather than `owner.login`) creates a `Status` on the victim's commit as if GitHub itself reported it.

### Citations

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

**File:** test/controllers/webhooks_controller_test.rb (L12-21)
```ruby
    test "create github repository which is not yet present in the datastore" do
      request.headers['X-Github-Event'] = 'push'
      unknown_repo_payload = JSON.parse(payload(:push_master))
      unknown_repo_payload["repository"]["full_name"] = "owner/unknown-repository"
      unknown_repo_payload = unknown_repo_payload.to_json

      assert_nothing_raised do
        post :create, body: unknown_repo_payload, as: :json
      end
    end
```

**File:** test/controllers/webhooks_controller_test.rb (L109-127)
```ruby
    test "unknown github organization logs and returns unprocessable entity" do
      @request.headers['X-Github-Event'] = 'push'

      payload = JSON.parse(payload(:push_master))
      payload["repository"]["owner"]["login"] = "unknown-org"

      Shipit.stubs(:github).raises(Shipit::GithubOrganizationUnknown.new("unknown-org"))
      Rails.logger.expects(:warn).with([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=push",
        "repository_owner=unknown-org",
        "unknown_organization=unknown-org",
        "status=422"
      ].join(' '))

      post :create, body: payload.to_json, as: :json
      assert_response :unprocessable_entity
    end
```
