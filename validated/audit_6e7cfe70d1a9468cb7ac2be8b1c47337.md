### Title
Webhook signature verification keys on `repository.owner.login` while the mutated repository is resolved from `repository.full_name` in the same body, letting a payload "verified" for a no-secret organization write records for a different organization's repository - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp`/`webhook_secret` to validate against using `repository.owner.login` (or `organization.login`) from the raw JSON body, but `Webhooks::Handlers::Handler#stacks` resolves the repository to mutate from `repository.full_name` in that same body. These two attacker-controlled fields are never checked for consistency, so if any organization configured in Shipit has a blank `webhook_secret`, an attacker can craft a body whose owner names that unsecured organization while `full_name` points at an unrelated, properly-secured organization's real repository, and the push handler will run against that real repository.

### Finding Description
The binding that should hold is: `org_that_verified_signature == org_that_owns_the_mutated_repository`, i.e. `params.dig('repository','owner','login')` (used to pick the `webhook_secret`) must equal the owner segment of `params.dig('repository','full_name')` (used to resolve `Repository`/`Stack`).

- `verify_signature` computes `repository_owner` from `params.dig('repository','owner','login')` / `params.dig('organization','login')` and fetches `Shipit.github(organization: repository_owner)`, then calls `verify_webhook_signature` [1](#0-0) [2](#0-1) .
- `GitHubApp#verify_webhook_signature` unconditionally returns `true` when `webhook_secret` is blank: `return true unless webhook_secret` [3](#0-2) .
- The handler base class resolves the repository to mutate from a completely different field, `payload.dig('repository', 'full_name')`, and loads its `stacks` via `Repository.from_github_repo_name(repository_name)` [4](#0-3) .
- `PushHandler#process` then iterates matching, non-archived stacks and calls `stack.sync_github(expected_head_sha: params.after)` [5](#0-4) .

Root cause: the controller never checks that the owner used for signature selection matches the owner embedded in `full_name`. As long as some organization configured in Shipit (`org-a`) has `webhook_secret` nil/blank, an attacker can POST a body with `repository.owner.login = "org-a"` (satisfying `return true unless webhook_secret`) and `repository.full_name = "org-b/real-repo"` naming a real, unrelated, properly-secured repository. `verify_signature` passes because `org-a` has no secret to check against; `PushHandler` then resolves and mutates `org-b`'s actual `Stack`/`Commit` rows via `sync_github`, without ever validating anything against `org-b`'s webhook secret.

None of the existing guards catch this: `drop_unhandled_event` only checks that a handler exists for the event type; the `ExplicitParameters` schema for `PushHandler` only requires `:ref` and `:after`, not any owner/full_name consistency; there is no `force_github_authentication`, `User#authorized?`, or model validation involved in this unauthenticated webhook path.

### Impact Explanation
A single crafted POST causes `Stack#sync_github` to run against a real repository/stack belonging to an organization whose webhook secret was never checked, i.e. "a payload for one repository mutating another's stack, commit, task" — matching the Critical impact category. This is repeatable against any repository/stack as long as its `full_name` is known (repo full names are public), and the blast radius spans every tenant/org hosted by the same Shipit instance, since the confusion is between `repository.owner.login` and `repository.full_name`, both fully attacker-controlled fields inside one JSON body.

### Likelihood Explanation
The exploit strictly depends on the Shipit deployment having at least one configured GitHub organization with a nil/blank `webhook_secret` (the code path `return true unless webhook_secret` explicitly permits this). This is an operator-configuration precondition, not something the attacker can create themselves — the attacker does not need to possess or forge any secret, they only need to know that such an org exists (or discover it by probing, since a nil-secret org accepts any signature/no signature). Given multi-org Shipit deployments where organizations can be onboarded before a webhook secret is set, or intentionally left unset, this is a realistic misconfiguration rather than a purely theoretical one, and the underlying code defect (no cross-check between the two owner-identifying fields) is present regardless of how many orgs are affected.

### Recommendation
In `WebhooksController#verify_signature`, additionally validate that the owner segment of `params.dig('repository','full_name')` matches `repository_owner` before dispatching to handlers, and reject the request (422) on mismatch. Additionally, reconsider `GitHubApp#verify_webhook_signature`'s `return true unless webhook_secret` fallback — organizations without a configured secret should not silently accept unsigned/unverified webhooks; either require a webhook secret for every configured organization or explicitly deny (rather than trust) webhooks for organizations with no secret configured.

### Proof of Concept
Minitest under `test/controllers/webhooks_controller_test.rb` (existing file):
1. Configure two orgs in `Shipit.github_apps`/test fixtures: `org-a` with `webhook_secret: nil`, `org-b` with a real `webhook_secret`.
2. Create a real `Shipit::Stack` for `org-b/real-repo` with a known `branch`.
3. POST to `/webhooks` with header `X-Github-Event: push`, no valid `X-Hub-Signature` (or an arbitrary bogus one), and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<some sha>",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/real-repo" }
}
```
4. Assert the response is `200 OK` (not `422`), proving `verify_signature` passed via `org-a`'s nil secret.
5. Assert that `Shipit::Stack.find_by(repository: Repository.from_github_repo_name('org-b/real-repo')).sync_github` was invoked / that a `GithubSyncJob` was enqueued for `org-b`'s stack — proving the equality `org_that_verified == org_that_owns_the_mutated_repo` is broken: verification happened against `org-a` (nil secret) while the mutation occurred on `org-b`'s repository.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
