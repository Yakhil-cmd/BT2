### Title
`push` webhook signature verified against `repository.owner.login`'s org while stack sync mutates the repository named in `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/org config to verify the HMAC signature using `repository_owner` (`params.dig('repository', 'owner', 'login')`), but `Handler#stacks` (used by `PushHandler`) resolves the target repository/stack using a completely different field, `payload.dig('repository', 'full_name')`. Because `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the selected org has no `webhook_secret` configured, an attacker can pick any no-secret org for `repository.owner.login` to make verification pass trivially, while pointing `repository.full_name` at an arbitrary victim repository whose stacks get synced.

### Finding Description
The broken binding: the code implicitly assumes `params.dig('repository','owner','login') == owner_of(params.dig('repository','full_name'))`, but nothing enforces this equality.

Path:
1. `WebhooksController#verify_signature` calls `Shipit.github(organization: repository_owner)` where `repository_owner` reads `params.dig('repository', 'owner', 'login')` [1](#0-0) [2](#0-1) .
2. `GitHubApp#verify_webhook_signature` short-circuits `return true unless webhook_secret`, i.e., if the selected org has no configured `webhook_secret`, the signature check is skipped entirely and the request is accepted regardless of headers/body [3](#0-2) .
3. Once past `verify_signature`, `WebhooksController#create` dispatches the raw parsed JSON to the handler for the event [4](#0-3) .
4. `PushHandler#process` calls `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }` [5](#0-4) .
5. `Handler#stacks` resolves the repository via `Repository.from_github_repo_name(repository_name)`, where `repository_name` is `payload.dig('repository', 'full_name')` — a field entirely independent of `repository.owner.login` used in step 1 [6](#0-5) .

Exploit: attacker crafts a JSON body with `repository.owner.login` set to any organization that has no `webhook_secret` configured in `Shipit.github` config (this could be an org the attacker controls, or any misconfigured org known to the attacker), and `repository.full_name` set to `victim-org/victim-repo`. Signature verification passes unconditionally because the secret-less org's check is a no-op. The `PushHandler` then locates and syncs the stacks belonging to `victim-org/victim-repo`, appending commits via `sync_github(expected_head_sha: params.after)`, potentially driving continuous delivery/deploys for a repository the attacker never authenticated against.

No existing guard prevents this: `drop_unhandled_event` only checks event type; `verify_signature` never cross-checks that the org used for HMAC verification matches the org that owns `repository.full_name`; `ExplicitParameters` schema for `PushHandler` only requires `:ref` and `:after`, not any owner/full_name consistency; there is no model-level validation tying webhook payload owner to the resolved `Repository`.

### Impact Explanation
An unauthenticated attacker can force a sync (`stack.sync_github`) against any repository/stack in the Shipit instance, provided any organization configured in `Shipit.github` lacks a `webhook_secret` (the attacker only needs to know or control one such org's name for the `owner.login` field — the field's actual ownership of the named repository is never checked). This is a payload for one repository (or a bogus owner) mutating another repository's stack — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team" / "unauthorized deploy". This is repeatable against any stack whose `full_name` the attacker knows, with no session, token, or secret required.

### Likelihood Explanation
Preconditions: at least one org registered in `Shipit.github` configuration must lack a `webhook_secret` (a common initial/misconfiguration state, and explicitly called out in the question as the scenario under test). Attacker cost is trivial — a single unauthenticated `POST /webhooks` with a crafted `push` JSON body and the `X-Github-Event: push` header; no signature is needed since the check short-circuits. This is fully repeatable against any target repository whose `full_name` is known (repository full names are public information on GitHub).

### Recommendation
Verify the webhook signature using the organization that actually owns `repository.full_name` (or, better, verify that `repository.owner.login` matches the owner segment parsed from `repository.full_name` before proceeding), and remove the `return true unless webhook_secret` unconditional-accept short-circuit in `GitHubApp#verify_webhook_signature` (or fail closed and reject webhooks for any org without a configured secret rather than accept them). Additionally, `PushHandler`/`Handler#stacks` should resolve repositories only from a field whose owner has been the one cryptographically verified.

### Proof of Concept
minitest plan (under `test/controllers/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers/push_handler_test.rb`, not written into `test/` by this response since it's out of scope for this audit, but the assertions to encode):

1. Configure `Shipit.github_config` (or stub `Shipit.github`) so org `"no-secret-org"` has no `webhook_secret`, and org `"victim-org"` has `webhook_secret: "victim-secret"`.
2. Create `victim_repository = Repository.create!(owner: "victim-org", name: "victim-repo")` and an associated non-archived `victim_stack` on branch `master` with a known `sha`.
3. POST to `/webhooks` with header `X-Github-Event: push`, no/garbage `X-Hub-Signature`, and JSON body:
   ```json
   { "repository": { "owner": { "login": "no-secret-org" }, "full_name": "victim-org/victim-repo" },
     "ref": "refs/heads/master", "after": "<new_sha_attacker_chooses>" }
   ```
4. Assert response is `200 OK` (not `422`), proving `verify_signature` passed despite no valid signature for `victim-org`.
5. Assert `victim_stack.reload` was synced / `sync_github` was invoked with `expected_head_sha: "<new_sha_attacker_chooses>"` — i.e., a stack belonging to `victim-org` (whose secret was never checked) was mutated by a request authenticated only against `no-secret-org`.
6. Equality check before: `repository_owner == "no-secret-org"` while `Repository.from_github_repo_name("victim-org/victim-repo").owner == "victim-org"` — these differ, proving the binding is broken, and the sync still executes.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
