### Title
Webhook signature is verified against the payload's `repository.owner.login`, but every event handler trusts the payload's `repository.full_name` to select the Stack/Commit to mutate - Repository confusion allows unauthorized cross-repository writes (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`, `app/models/shipit/webhooks/handlers/push_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, taken from `params.dig('repository', 'owner', 'login')` (or `organization.login`). Once the HMAC check passes, every downstream `Webhooks::Handlers::Handler` subclass instead resolves the target `Stack`/`Repository`/`Commit` using a *different* field of the same attacker-controlled JSON body: `payload.dig('repository', 'full_name')` (`Handler#repository_name`, `Handler#stacks`) or bare `Commit.where(sha: params.sha)` (`StatusHandler`). Nothing cross-checks that `repository.full_name` actually belongs to the organization/owner that the signature was verified against.

### Finding Description
The binding that should hold is: **organization authenticated by the webhook signature == repository being written to**. Instead, this holds:

- Authenticated by signature: `repository.owner.login` (or `organization.login`), used only in `Shipit.github(organization: repository_owner)` to pick the webhook secret, at `app/controllers/shipit/webhooks_controller.rb:24-30,59-62`.
- Repository actually mutated: `repository.full_name`, used in `app/models/shipit/webhooks/handlers/handler.rb:33-38` (`stacks` / `repository_name`), and reused identically in `PushHandler`, `PullRequest::OpenedHandler`, `PullRequest::AssignedHandler`, `PullRequest::ReopenedHandler`, etc.

An attacker who legitimately owns a GitHub organization/App integrated with this Shipit instance (i.e., who knows *their own* `webhook_secret`, which is a normal, unprivileged, self-service credential any org admin can set when installing/configuring their own GitHub App on this Shipit instance) can produce a validly-signed webhook body where:
- `repository.owner.login` = `"attacker-org"` (so `verify_webhook_signature` picks attacker-org's `webhook_secret` and the HMAC matches, since the attacker computed it themselves)
- `repository.full_name` = `"victim-org/victim-repo"` (a Stack/Repository the attacker doesn't own)

Because `verify_signature` never checks that `repository.full_name`'s owner segment equals `repository_owner`, the signature check passes, and the handler then operates on the victim's Stack.

Concretely:
- `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) will call `stack.sync_github(expected_head_sha: params.after)` on the victim's not-archived stacks matching `branch`, forcing `GithubSyncJob` to run against the victim repository with an attacker-chosen `expected_head_sha`.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) is worse: it doesn't even use `repository.full_name` — it looks up `Commit.where(sha: params.sha)` globally across the whole database and calls `commit.create_status_from_github!(params)`. Since commit `sha`s are public git hashes, an attacker who validly signs a request under their own org's secret can inject arbitrary CI status (`state: "success"`, `context`, etc.) for **any commit belonging to any stack in the Shipit instance**, including ones on repositories they have no relationship with.
- `PullRequest::OpenedHandler` can create Review Stacks, and `ReopenedHandler` can `unarchive!` stacks belonging to victim repositories, again gated only by `repository.full_name` in the payload.

### Impact Explanation
Forging a commit `status` webhook (`state: "success"`) for an arbitrary commit sha on a stack the attacker doesn't control can mark that commit `deployable?` and (depending on stack configuration) satisfy `require_ci` checks used by `Deploy#trigger_deploy`/`stack.trigger_deploy` (`app/controllers/shipit/api/deploys_controller.rb:20-27`) or automatic/continuous deployment (`Stack.schedule_continuous_delivery`), and can influence merge-queue eligibility, which is checked via commit deployability in `merge_request`/`merge_status` flows. This is an unauthorized-deploy/merge-adjacent primitive: an attacker with no privileges on the victim's repository or Shipit stack can forge a positive CI signal that the victim's own deploy/merge automation then trusts, matching the "unauthorized deploy, rollback, or merge" Critical category, and at minimum is a cross-repository/cross-stack write (Critical) since state belonging to another repository's commit records is mutated without any authorization tied to that repository.

### Likelihood Explanation
Likelihood is high for any Shipit instance that federates multiple independent GitHub organizations/Apps (the multi-org config format shown in `config/secrets.development.example.yml` is explicitly supported), since each org's admin legitimately possesses their own `webhook_secret` and can freely craft the JSON body sent to the shared `/webhooks` endpoint — this requires no compromise of the victim, no GitHub App private key, and no Shipit account; it only requires being one of the (potentially many) organizations already onboarded to the shared Shipit instance.

### Recommendation
In `WebhooksController#verify_signature` (or, better, inside `Shipit::Webhooks::Handlers::Handler`), after signature verification succeeds, assert that `repository.full_name`'s owner segment (and/or `organization.login` for org-level events) equals the `repository_owner`/organization whose secret validated the signature, rejecting (422) any payload where they diverge. Additionally, `StatusHandler` should scope `Commit.where(sha: params.sha)` to commits whose `stack.repository.owner` matches the verified organization, rather than searching globally.

### Proof of Concept
1. Attacker legitimately administers GitHub org `attacker-org`, which is configured in this Shipit instance with `webhook_secret = S`.
2. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "<victim-commit-sha-known-publicly>",
  "state": "success",
  "context": "ci/attacker-forged",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(S, body)` themselves (they legitimately know `S`) and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and the HMAC matches → passes.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim's commit anywhere in the DB — and calls `commit.create_status_from_github!(params)`, writing a forged successful CI status onto a commit in `victim-org/victim-repo` that the attacker never authenticated against. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
