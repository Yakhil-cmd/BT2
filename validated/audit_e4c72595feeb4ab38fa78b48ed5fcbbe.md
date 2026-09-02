### Title
Webhook org used for HMAC verification is decoupled from the repository owner used for record writes, enabling cross-tenant Stack/Commit mutation - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/handler.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/`webhook_secret` to verify against using `params.dig('repository', 'owner', 'login')`, while `Webhooks::Handlers::Handler#repository_name` (used by every handler including `PushHandler`, `CheckSuiteHandler`) resolves the target `Repository`/`Stack` using the independent field `params.dig('repository', 'full_name')`. Because both fields live in the same attacker-controlled, not-yet-verified JSON body and are never cross-checked, an attacker who owns a legitimately-configured org in a multi-tenant Shipit install can sign a payload with their own `webhook_secret` while pointing `full_name` at a victim org/repo, causing handlers to run privileged database writes against the victim's `Stack`.

### Finding Description
The broken binding, stated as an equality that the code implicitly assumes but never enforces:
`Shipit.github(organization: params.dig('repository','owner','login')).organization` == `Repository.from_github_repo_name(params.dig('repository','full_name')).owner`

In `verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49), the app used to verify the HMAC is chosen via `repository_owner`: [1](#0-0) 
which only reads `repository.owner.login` (or `organization.login`).

Once verification succeeds (`head(:ok)` path), `create` dispatches the raw, attacker-supplied `params` to handlers: [2](#0-1) 

Every handler resolves the target repository/stacks via `Handler#repository_name`, which reads a **different** JSON field, `repository.full_name`, not `repository.owner.login`: [3](#0-2) 

`Repository.from_github_repo_name` splits `full_name` on `/` and looks up the `Repository` row purely by that string, with no relation to which org's secret verified the request: [4](#0-3) 

`PushHandler#process` then runs `stack.sync_github` for every non-archived stack on branch match: [5](#0-4) 

**Exploit flow:** the attacker owns `attacker-org`, which is legitimately onboarded to this Shipit instance (per the documented multi-org setup) and therefore the attacker knows `attacker-org`'s real `webhook_secret` (it's their own GitHub App webhook config). The attacker crafts a JSON body with `repository.owner.login = "attacker-org"` and `repository.full_name = "victim-org/victim-repo"`, computes `X-Hub-Signature` with `attacker-org`'s webhook_secret over that exact body, and POSTs it to `/webhooks` with `X-Github-Event: push`.
- `verify_signature` computes `repository_owner = "attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and `verify_webhook_signature` succeeds because the attacker legitimately signed with their own secret over the exact bytes.
- `PushHandler.call(params)` resolves `repository_name = "victim-org/victim-repo"`, finds the real victim `Repository`/`Stack`, and calls `stack.sync_github(expected_head_sha: params.after)` — a write triggered by a request that `victim-org` never authenticated.

No existing guard closes this gap: `drop_unhandled_event` only checks the event type; `ExplicitParameters` schemas per handler validate field *types*, not cross-field consistency with the verifying org; there is no code anywhere that asserts `repository.owner.login == repository.full_name.split('/').first`, nor that the org used for HMAC verification matches the org whose `Stack` is mutated.

### Impact Explanation
A payload signed by `attacker-org`'s own `webhook_secret` triggers writes/side-effects scoped to a victim's `Repository`/`Stack` (e.g., `Stack#sync_github` via `GithubSyncJob`, and analogously `CheckSuiteHandler` scheduling check-run refreshes on victim stacks). This is a cross-tenant integrity violation: the tenant whose secret verified the request is not the tenant whose data is mutated. It is repeatable against any victim repository already onboarded in the same Shipit instance, for every push/check_suite event the attacker cares to forge, matching the "Critical: payload for one repository mutating another's stack/commit/task" category. Note `StatusHandler#process` is even broader — it looks up `Commit.where(sha: params.sha)` with no repository scoping at all, so a forged `status` event signed by any onboarded org's secret can attach a fabricated CI status to any commit sha in the entire instance, further amplifying blast radius. [6](#0-5) 

### Likelihood Explanation
Preconditions: Shipit must be configured for multiple organizations (the documented multi-app setup in `config/secrets.yml` / `docs/setup.md`), and the attacker must control at least one legitimately onboarded org (their own) with a known `webhook_secret` — plausible in any SaaS-like or self-serve onboarding scenario. No victim secret, session, or API token is needed. The attacker's cost is a single crafted HTTP POST with a valid HMAC over their own chosen body; it is trivially repeatable against any target `full_name` already tracked by Shipit.

### Recommendation
Enforce equality between the field used for signature-verification org selection and the field used for record resolution before dispatching to handlers — e.g., in `WebhooksController#verify_signature`/`create`, derive the target org from the same trusted source used to pick the verifying app (or, better, resolve `Repository`/`Stack` using `repository.owner.login` consistently, and reject the payload if `repository.full_name`'s owner segment doesn't match `repository.owner.login`). Additionally, scope `StatusHandler`'s `Commit` lookup to the verified organization instead of a global `Commit.where(sha: ...)` scan.

### Proof of Concept
minitest test in a controller test (conceptually, not to be placed in `test/**` per scope note, but for the purpose of illustrating the two sides of the equality):
1. Configure two orgs in test secrets, `attacker-org` and `victim-org`, each with distinct `webhook_secret`s (using fixture pattern from `test/dummy/config/secrets_double_github_app.yml`).
2. Create a real `Shipit::Repository`/`Shipit::Stack` for `victim-org/victim-repo`.
3. Build a `push` payload JSON with `repository.owner.login = "attacker-org"` and `repository.full_name = "victim-org/victim-repo"`.
4. Compute `X-Hub-Signature` using `attacker-org`'s `webhook_secret` over the raw JSON body.
5. POST to `/webhooks` with that signature and `X-Github-Event: push`.
6. Assert `response` is `:ok` (verification passed against `attacker-org`), and assert `GithubSyncJob`/`stack.sync_github` was invoked for the `victim-org/victim-repo` `Stack` — i.e., `Shipit.github(organization: "attacker-org")` is the org that "verified" while `Repository.from_github_repo_name("victim-org/victim-repo").owner == "victim-org"` is the org actually mutated, proving the two sides of the equality diverge.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
