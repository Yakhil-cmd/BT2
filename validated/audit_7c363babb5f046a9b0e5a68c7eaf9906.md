### Title
Cross-Organization Webhook Forgery via Mismatched Signature-Verification Field vs. Handler-Consumed Field - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and thus the webhook secret) used to authenticate an inbound webhook based on `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`), but the event handlers that actually act on the payload (e.g. `Handler#repository_name`, used by `PushHandler`) resolve the target `Repository`/`Stack` from a completely different field, `payload.dig('repository', 'full_name')`. In a multi-organization Shipit deployment (explicitly supported, see `test/dummy/config/secrets_double_github_app.yml` and `docs/setup.md`'s "multiple Github applications" section), these two fields are never checked for consistency, so a webhook signed with *one* organization's secret can be crafted to act on a *different* organization's stack.

### Finding Description
`Shipit::WebhooksController#verify_signature` picks the signing secret to validate against like this: [1](#0-0) 
with `repository_owner` defined as: [2](#0-1) 

Once the signature is accepted, the raw JSON is dispatched to handlers unmodified: [3](#0-2) 

`Handlers::Handler`, the base class used by `PushHandler`, resolves the target repository/stack from a *different* JSON path than the one used for signature selection: [4](#0-3) 

`PushHandler` then calls `stack.sync_github(expected_head_sha: params.after)` on every non-archived stack matching that repository/branch: [5](#0-4) 

Because signature verification is keyed off `repository.owner.login` while the handler dispatch is keyed off `repository.full_name`, an attacker who legitimately controls the webhook secret for *their own* organization/GitHub App configured in the same multi-tenant Shipit instance can craft a raw JSON body where:
- `repository.owner.login` = their own org (so `Shipit.github(organization: ...)` picks their own known secret and the HMAC check passes), and
- `repository.full_name` = `"victim-org/victim-repo"` (an unrelated stack tracked by the same Shipit instance).

This is the exact class of bug described in the source report: a value used for the trust/authorization decision (`auction.seller` / here, the org used to verify the signature) is decoupled from a related value that is acted upon (`buyPrice.seller` / here, the repository the handler actually mutates), because the protocol/engine never re-validates that the two stay in sync.

### Impact Explanation
This breaks the binding "organization that authenticated == repository that is written." An entity with no Shipit account, no API token, and no GitHub write access to the victim repository can force `Shipit::Webhooks.for_event('push')` handlers to execute against a stack belonging to a completely different, unrelated GitHub organization tracked by the same Shipit instance. At minimum this forces unauthorized `GithubSyncJob` execution (writing `Commit`/`Status` records for a repository/org the attacker has no authorization over) purely by presenting credentials for an unrelated tenant. On stacks with `continuous_deployment` enabled, forcing a resync at an attacker-chosen time can also force the timing of an otherwise-scheduled/legitimate deploy to occur under attacker control, i.e., an unauthorized deploy trigger across a repository/organization boundary the attacker was never granted access to.

### Likelihood Explanation
This requires the Shipit instance to be configured to host multiple GitHub organizations/GitHub Apps behind the same `/webhooks` endpoint — an explicitly documented and supported configuration (`docs/setup.md`, `test/dummy/config/secrets_double_github_app.yml`). Any tenant/org admin onboarded onto such a shared instance already knows their own app's `webhook_secret` (they configure it themselves when creating their GitHub App per the setup docs) and can freely craft arbitrary raw JSON bodies signed with it, since `verify_signature` never checks that the org used for verification matches the org embedded in `repository.full_name`.

### Recommendation
After signature verification, assert that `repository_owner` (the org used to select/verify the webhook secret) matches the owner segment of `repository.full_name` (and `organization.login` for org-scoped events) before dispatching to any handler. Reject the webhook with 422 if they diverge.

### Proof of Concept
1. Shipit is configured with two GitHub Apps, `OrgAttacker` and `OrgVictim` (as in `test/dummy/config/secrets_double_github_app.yml`), each with its own `webhook_secret`.
2. Attacker, who administers `OrgAttacker`'s GitHub App, knows `OrgAttacker`'s webhook secret.
3. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "repository": { "owner": { "login": "OrgAttacker" }, "full_name": "OrgVictim/victim-repo" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>"
}
```
   signed with `X-Hub-Signature: sha1=<HMAC(OrgAttacker_webhook_secret, body)>`.
4. `verify_signature` computes `repository_owner = "OrgAttacker"`, loads `OrgAttacker`'s `GitHubApp`, and the signature validates successfully.
5. `PushHandler#process` resolves the target via `payload.dig('repository', 'full_name')` = `"OrgVictim/victim-repo"`, looks up that `Stack`, and invokes `stack.sync_github(expected_head_sha: ...)` — action taken against a repository/organization the attacker has no legitimate relationship with in Shipit, despite having authenticated with a different organization's credentials entirely.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
