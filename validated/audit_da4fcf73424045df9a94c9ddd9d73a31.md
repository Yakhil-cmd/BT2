Confirmed vulnerability found: the webhook signature verification key is selected using `repository_owner` (from `params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`), while the actual repository acted upon by handlers is looked up separately from `payload.dig('repository', 'full_name')` — a field never covered by the signature-selection binding.

### Title
Webhook signature is verified against `repository.owner.login`/`organization.login` while handlers act on the independently-controlled `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`) [1](#0-0) [2](#0-1) . However, once the signature check passes, the raw parsed `params` are handed unmodified to the registered event handlers, which independently derive the target repository from `payload.dig('repository', 'full_name')` via `Handler#repository_name`/`#stacks` [3](#0-2) , and `Repository.from_github_repo_name` splits that string on `/` to find the owning repo record [4](#0-3) . The binding the signature check is supposed to establish — "the organization whose secret authenticated this payload" == "the repository the payload's data will be applied to" — is never enforced, exactly mirroring the report's core defect: a security check (self-service enabled / signature ownership) that does not correspond to the field actually acted upon (the `self_service` flag passed to `create_pending_transaction` / the `repository.full_name` used for the actual mutation).

### Finding Description
`verify_signature` computes `repository_owner` from `repository.owner.login`, and if that key is absent, from a **top-level** `organization.login` field — a fallback intended for organization-scoped events like `membership` [2](#0-1) . That owner is used to fetch the correct `Shipit.github(organization: repository_owner)` instance and verify the raw HMAC signature with that organization's configured `webhook_secret` [1](#0-0) . If verification succeeds, the controller does **not** re-derive or cross-check the repository the payload will actually operate on — it simply dispatches the full, attacker-controlled JSON body to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [5](#0-4) .

For the `push` event, `PushHandler#process` resolves stacks purely from `payload.dig('repository', 'full_name')` through `Handler#stacks`/`#repository_name` [3](#0-2)  and then calls `stack.sync_github(expected_head_sha: params.after)` on every matching, non-archived stack with the matching branch [6](#0-5) . Because `repository.owner.login` (used for signature selection) and `repository.full_name` (used for the actual repository/stack lookup) are two independent fields inside the same JSON body that the attacker fully controls up to producing a valid HMAC for *some* organization they know the secret of, an attacker who possesses (or compromises) the `webhook_secret` for organization A can craft a payload whose `repository.owner.login` is `A` (so the signature check passes) but whose `repository.full_name` is `B/some-repo` (a completely different organization/repository configured in the same Shipit instance). The signature check "authenticates" organization A, but the mutation is applied against repository B's stacks.

This reproduces the report's root cause pattern precisely: a check is performed on one representation of "who is authorized" while the actually-consumed/actioned value is a separate, unverified field — just as `request_self_service_share_transfer` checked several conditions but never checked `self_service`, and passed a hardcoded `false` disconnected from the real self-service state to `create_pending_transaction`.

### Impact Explanation
This breaks the binding `{organization authenticated via webhook_secret} == {repository whose stacks are mutated}`. A `push` webhook forged this way triggers `stack.sync_github(expected_head_sha:)`, which updates commit history/HEAD tracking for stacks belonging to a repository the attacker does not control and was not authorized to send events for, using only knowledge of a *different* organization's `webhook_secret`. Depending on downstream deploy triggers (e.g., continuous deployment configured on the target stack), this can lead to unauthorized syncing/deploy triggering against a repository the attacker has no legitimate relationship with, meeting the "unauthorized deploy" impact bar in the rules.

### Likelihood Explanation
Likelihood is bounded by needing knowledge of *some* valid `webhook_secret` for *some* organization/repo configured on the same Shipit instance (an attacker who is an authorized GitHub webhook sender for organization A, or who leaked A's secret through any means) — they need no privileges over organization/repository B at all. Multi-tenant Shipit deployments hosting many unrelated orgs/repos are the primary risk scenario. This is a plausible, low-complexity exploitation once one valid secret is known, matching the report's "Low difficulty" rating for a control that is checked but not tied to the actually-affected resource.

### Recommendation
In `WebhooksController#verify_signature`, after determining `repository_owner` and validating the signature, re-validate that the payload's `repository.full_name` (used later by `Handler#stacks`) belongs to the same verified organization/owner before dispatching to handlers — e.g., assert `params.dig('repository', 'full_name')&.split('/')&.first&.casecmp?(repository_owner)`, rejecting with `422` on mismatch. More robustly, have `Handler#stacks` receive the verified organization from the controller and filter/scope repository lookup by it rather than trusting the unauthenticated `full_name` field independently.

### Proof of Concept
1. Attacker controls (or has learned) the `webhook_secret` configured for organization `orgA` (e.g., via a legitimately configured GitHub App/webhook they operate for `orgA`, or a leaked secret).
2. Attacker crafts a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "deadbeef",
     "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/target-repo" }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(orgA_webhook_secret, raw_body)>` and POSTs to `/webhooks` with header `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` = `"orgA"`, fetches `Shipit.github(organization: "orgA")`, and the HMAC check passes because the attacker knows `orgA`'s secret [1](#0-0) .
5. `PushHandler#process` resolves `repository_name` from `full_name` = `"orgB/target-repo"`, finds `orgB`'s stacks via `Repository.from_github_repo_name` [4](#0-3) , and calls `stack.sync_github(expected_head_sha: "deadbeef")` on matching stacks belonging to `orgB` — an organization the attacker never authenticated against.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
