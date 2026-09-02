### Title
Webhook signature verified against one organization's secret while the write target (repository/commit) is taken from an unrelated payload field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook by picking a GitHub App/organization config keyed off `repository.owner.login` (or `organization.login`) and validating the HMAC signature against that organization's `webhook_secret`. However, the handlers that actually perform writes (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) resolve their write target from a *different, unrelated* payload field (`repository.full_name` for stack lookup, or no repository scoping at all for `StatusHandler`). Because the field used to select the verifying secret is never cross-checked against the field used to select the write target, an operator of any organization configured on a shared multi-org Shipit instance can forge a payload that is authenticated with their own legitimately-known secret but that writes to a completely different organization's repositories/commits.

### Finding Description
Shipit supports hosting multiple GitHub organizations from one instance, each with its own `webhook_secret` (`config/secrets.development.example.yml` documents this per-org `github: <org>: webhook_secret:` layout). At request time: [1](#0-0) 

selects the GitHub App/secret via `Shipit.github(organization: repository_owner)`, where: [2](#0-1) 

`repository_owner` reads `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`) straight out of the attacker-controlled raw JSON body — the same body the attacker crafts and signs.

Once `verify_signature` passes, `Shipit::Webhooks.for_event(event)` dispatches the *same* raw params to handlers. The base `Handler` class resolves the actual write target from a different field, `repository.full_name`: [3](#0-2) 

`PushHandler` uses this `stacks` scoping to trigger `stack.sync_github`: [4](#0-3) 

`StatusHandler` is even weaker — it performs **no repository/stack scoping whatsoever** and simply looks up any commit in the entire database by `sha`: [5](#0-4) 

There is no code anywhere that checks `repository.owner.login` (used to select the verifying secret) is consistent with `repository.full_name`/the commit's owning stack (used to decide what gets written). The binding that should hold — `organization that authenticated == repository/commit that is written` — is broken.

### Impact Explanation
An attacker who legitimately administers any single organization hosted on a shared Shipit instance (and therefore knows/controls that org's `webhook_secret`, since they configured the GitHub App webhook themselves) can:
1. Sign an arbitrary JSON body with their own org's secret, satisfying `verify_webhook_signature`.
2. Set `repository.owner.login`/`organization.login` to their own org (so the correct secret is picked) while setting `repository.full_name` (for push/check_suite) or simply supplying an arbitrary `sha` (for `status`, which isn't scoped at all) to target any other tenant's repository or commit.
3. Forge a `status` event with `state: "success"` for a known commit SHA belonging to a victim stack they do not own. Because CI/status gating drives `deployable?`, required statuses, and the merge queue, this can be used to make an otherwise-failing or unchecked commit appear CI-green, enabling an **unauthorized merge or deploy** on a repository the attacker has no access to. It can also forge `push`/`check_suite` events to force spurious `GithubSyncJob`/`RefreshCheckRunsJob` runs against arbitrary stacks.

This matches the "unauthorized deploy, rollback, or merge" High/Critical impact bucket, since CI gating is subverted for a repository outside the attacker's authorization boundary, purely through a credential (webhook secret) they legitimately hold for an unrelated tenant.

### Likelihood Explanation
This requires the deployment to be configured for multiple GitHub organizations sharing one Shipit instance (a documented, supported configuration — see `config/secrets.development.example.yml`), and requires the attacker to control (administer) at least one of those organizations, which is an unprivileged position relative to any *other* tenant's repositories. No repository write access, no `ApiClient` token, and no session on the victim organization are needed — only the ability to send an HTTP POST to `/webhooks` with a body signed by a secret the attacker legitimately possesses for their own org.

### Recommendation
After computing `repository_owner` for secret selection, re-derive the same organization identity from `repository.full_name` (or the resolved `Repository`/`Stack`) and require they match before processing the event; alternatively, have handlers resolve their target repository strictly from the same field used for signature/organization resolution (`repository.owner.login`) rather than `repository.full_name`, and add explicit organization scoping to `StatusHandler`'s commit lookup.

### Proof of Concept
1. Shipit is configured with two organizations, `attacker-org` and `victim-org`, each with a distinct `webhook_secret` (per the multi-org config format).
2. Attacker legitimately owns `attacker-org` and therefore knows `attacker-org`'s `webhook_secret` (they set it when creating the GitHub App webhook).
3. Attacker crafts a `status` event payload:
```json
{
  "sha": "<victim commit sha, e.g. scraped from a public PR or Shipit UI>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
4. Attacker computes `X-Hub-Signature` using `attacker-org`'s webhook secret and POSTs to `/webhooks` with header `X-Github-Event: status`.
5. `WebhooksController#verify_signature` computes `repository_owner = "attacker-org"`, loads `attacker-org`'s secret, and the signature validates successfully.
6. `StatusHandler#process` ( [5](#0-4) ) looks up `Commit.where(sha: params.sha)` with no organization scoping, and records a forged "success" status against the victim's commit, which is used elsewhere in Shipit for CI-gating decisions.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
