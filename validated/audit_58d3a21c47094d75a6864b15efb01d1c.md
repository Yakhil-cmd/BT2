## Finding

### Title
Webhook signature verification key is selected by an unverified payload field, decoupling the authenticated GitHub organization from the repository/commit actually written - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification based on `repository_owner`, a field read directly out of the *unverified* JSON body [1](#0-0) . The value used to pick the verification key is not itself covered by the resulting signature check in any way that binds it to the data the handlers subsequently act on, because handlers key their database writes off a different, independently-controlled field: `repository.full_name` (or, worse, no repository scoping at all).

### Finding Description
`repository_owner` is computed as:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

This value is passed to `Shipit.github(organization: repository_owner)` to obtain the `GitHubApp` instance whose `webhook_secret` is used to verify `X-Hub-Signature` [1](#0-0) . Shipit explicitly supports hosting multiple GitHub organizations, each with its own independent `webhook_secret`, as documented in `docs/setup.md` and `config/secrets.development.example.yml` (multi-org config block) [3](#0-2) .

Once the signature is accepted, `WebhooksController#create` dispatches the *entire raw payload* to handlers keyed only by event type, with no re-validation that the data inside matches the organization whose secret was used to authenticate the request:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [4](#0-3) 

Handlers derive the target repository from `payload.dig('repository', 'full_name')`, a completely separate field from the one used for signature-key selection:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
``` [5](#0-4) 

`PushHandler` uses this to sync arbitrary stacks with an attacker-chosen `after` SHA [6](#0-5) . `CheckSuiteHandler` likewise scopes to `stacks` derived from `repository.full_name` [7](#0-6) . Most severely, `StatusHandler` doesn't even scope by repository at all — it matches on `Commit.where(sha: params.sha)` across the *entire* Shipit instance, writing a CI status for any commit anywhere that happens to share the given SHA:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [8](#0-7) 

This is exactly the equality the analog rules call out: **the organization that authenticated the request ≠ the repository (or commit) that is actually written**. The field bound by the signature (`repository.owner.login` used only to pick a secret) is not the same field the handler logic trusts to select what gets mutated.

### Impact Explanation
In a multi-organization Shipit deployment, an attacker who legitimately administers their own low-value GitHub organization's App integration (and therefore legitimately knows *that* organization's `webhook_secret` — not the victim's) can:
1. Sign a webhook payload with their own org's secret (`repository.owner.login: "attacker-org"`, or `organization.login` for events like `membership`).
2. Set `repository.full_name` (or `check_suite`/`sha` fields) inside the same payload to point at a victim repository/stack/commit hosted on the same Shipit instance under a different, unrelated organization.
3. Have `WebhooksController#verify_signature` pass (it only checks the signature against the attacker's own known secret) and have the handler act on the victim's data — e.g. `PushHandler` triggering `stack.sync_github(expected_head_sha: ...)` on the victim's stack with an attacker-chosen commit SHA, or `StatusHandler` forging a commit status on an unrelated commit anywhere in the instance, which can influence Shipit's automatic-merge/deploy gating logic.

This crosses a repository/organization trust boundary without any privileged credential belonging to the victim, resulting in cross-repository writes / manipulation of deploy-relevant state — matching the Critical/High impact bar ("cross-repository writes", "unauthorized deploy, rollback or merge").

### Likelihood Explanation
Requires only that the attacker controls (or is a legitimate but low-trust member of) at least one GitHub organization configured on the same multi-tenant Shipit instance — a configuration explicitly documented and supported by Shipit itself [3](#0-2) . No `webhook_secret`, `api_clients_secret`, GitHub App private key, or session of the victim organization is needed; the attacker only needs their own organization's secret, which they legitimately possess as its administrator.

### Recommendation
Bind signature-key selection to the same trust boundary the handlers rely on for writes. At minimum: (1) after verifying the signature with the key selected by `repository_owner`, re-derive `repository.full_name`'s owner and require it to exactly match `repository_owner`, rejecting the webhook otherwise; (2) have every handler (`StatusHandler` in particular) scope all lookups (e.g., `Commit.where(sha: ...)`) through the repository/stack whose organization matches the one that produced the valid signature, never through globally-unscoped queries.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` (secret `S1`, controlled by attacker) and `victim-org` (secret `S2`, unknown to attacker), as supported per `docs/setup.md`.
2. Craft a `push` webhook body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Compute `X-Hub-Signature` using `S1` (`attacker-org`'s secret, known to the attacker).
4. POST to `/webhooks` with `X-Github-Event: push`. `verify_signature` selects `Shipit.github(organization: "attacker-org")` and verifies successfully against `S1` [1](#0-0) .
5. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` [9](#0-8)  and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's stack [6](#0-5)  — despite the request having been authenticated only against `attacker-org`'s credentials.

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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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
