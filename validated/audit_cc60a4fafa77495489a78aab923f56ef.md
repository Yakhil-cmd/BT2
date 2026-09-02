### Title
Webhook signature is verified against `repository.owner.login` while the stack lookup uses `repository.full_name` — an attacker owning one connected GitHub org can trigger `sync_github` on any other org's `Stack` - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp`/`webhook_secret` to validate the HMAC using `repository.owner.login` from the JSON body, but `Handler#stacks` resolves the target `Repository`/`Stack` using an independently-read field, `repository.full_name`, via `Repository.from_github_repo_name`. Because these two payload fields are never cross-checked, an attacker who owns one GitHub org connected to the Shipit instance (and thus knows that org's real `webhook_secret`) can sign a push payload whose `repository.owner.login` is their own org (passing signature verification) while `repository.full_name` names a completely different, victim org's repository, causing `PushHandler#process` to call `stack.sync_github(expected_head_sha: params.after)` on the victim's `Stack` with an attacker-chosen SHA.

### Finding Description
The claimed binding, stated as an equality, is:
`org(webhook_secret that verified HMAC) == org(owner of Repository/Stack that sync_github executes against)`

Tracing the code shows this equality is **not enforced**:
- `WebhooksController#repository_owner` reads `params.dig('repository', 'owner', 'login')` and uses it to pick the `GitHubApp` config (and thus the `webhook_secret`) for signature verification: [1](#0-0) [2](#0-1) 
- After the signature passes, `Handler#stacks` resolves the target repository/stack from a **different** field, `payload.dig('repository', 'full_name')`: [3](#0-2) 
- `Repository.from_github_repo_name` splits the owner/name directly out of that `full_name` string with no relation to `repository.owner.login`: [4](#0-3) 
- `PushHandler#process` then runs `stack.sync_github(expected_head_sha: params.after)` for every non-archived stack on that resolved repository matching the branch, using an attacker-fully-controlled `after` SHA: [5](#0-4) 

Exploit flow: the attacker sends `POST /webhooks` with header `X-Github-Event: push`, and a JSON body where `repository.owner.login = "attacker-org"` (the org for which the attacker legitimately knows the configured `webhook_secret`) but `repository.full_name = "victim-org/victim-repo"` (naming a `Stack` belonging to a different, unrelated org on the same Shipit instance). The attacker signs the raw body with `attacker-org`'s real secret via HMAC-SHA1 in `X-Hub-Signature`. `verify_signature` looks up the `GitHubApp` for `attacker-org`, computes the HMAC with the correct (attacker-known) secret, and passes. Control then reaches `PushHandler#process`, which resolves the target `Stack` purely from `full_name`, i.e., the victim's stack, and calls `sync_github` with the attacker's chosen `after` value.

None of the existing guards close this gap: `drop_unhandled_event` only filters by event type, not repository identity; `ExplicitParameters` (`params do requires :ref; requires :after end`) only validates presence/shape of `ref`/`after`, not repository consistency; there is no `User#authorized?`/`require_permission!` check anywhere in this controller (it's a machine-to-machine webhook endpoint, not a user session flow); and there is no code anywhere that asserts `repository.owner.login == repository.full_name.split('/').first`.

### Impact Explanation
This lets a request authenticated only for one GitHub org's webhook cause `Stack#sync_github` to run for a `Stack` belonging to a completely different, unrelated org/tenant on the same Shipit instance, with an attacker-chosen `expected_head_sha`. This is a payload for one repository mutating another repository's stack state — a cross-tenant write triggered without the victim's org's `webhook_secret` ever being involved, matching the Critical category "a payload for one repository mutating another's stack, commit, task or task." It is repeatable against any stack on any org configured on the shared instance, as long as the attacker knows at least one other configured org's own webhook secret (their own).

### Likelihood Explanation
Preconditions: the Shipit instance must be configured for multi-organization webhooks (multiple `Shipit.github(organization: ...)` configs, i.e., a shared instance serving multiple GitHub orgs/tenants), and the attacker must legitimately own/control one of those connected orgs (and thus know its real `webhook_secret`). Given that, the attack cost is a single crafted HTTP POST with a valid HMAC signed with the attacker's own known secret — no Shipit session, API token, or victim secret is required. This is fully attacker-driven and repeatable at will.

### Recommendation
Cross-validate the owner used for signature verification against the owner encoded in `repository.full_name` before dispatching to any handler — e.g., in `WebhooksController#create`/`verify_signature`, require that `params.dig('repository', 'full_name')&.split('/')&.first&.downcase == repository_owner.downcase` (and likewise for `organization.login` fallback), rejecting the request (422) on mismatch. Alternatively, have `Handler#stacks` resolve strictly from the same owner value that was used to verify the signature, rather than independently re-deriving it from `full_name`.

### Proof of Concept
Minitest integration test plan (`test/controllers/webhooks_controller_test.rb` style, no live GitHub):
1. Configure two orgs in test secrets/config: `attacker-org` with a known `webhook_secret_a`, and `victim-org` with `webhook_secret_v`.
2. Create a `Stack` under `victim-org/victim-repo` with `branch: "master"`.
3. Build a push payload JSON with `repository.owner.login = "attacker-org"`, `repository.full_name = "victim-org/victim-repo"`, `ref = "refs/heads/master"`, `after = "deadbeef...attackersha"`.
4. Sign the raw body with `webhook_secret_a` (attacker-known) and set `X-Hub-Signature` accordingly; set `X-Github-Event: push`.
5. POST to `/webhooks`.
6. Assert the response is `200 OK` (signature accepted for `attacker-org`).
7. Assert (e.g., via mocking/stubbing `Stack#sync_github`) that `sync_github` was called on the `victim-org/victim-repo` stack with `expected_head_sha: "deadbeef...attackersha"` — demonstrating that `webhook_secret_a` (bound to `attacker-org`) authorized a mutation targeting `victim-org`'s stack, breaking the claimed equality `org(secret that verified HMAC) == org(stack mutated)`.

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
