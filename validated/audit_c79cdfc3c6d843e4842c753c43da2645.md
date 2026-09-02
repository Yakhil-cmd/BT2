### Title
Webhook signature verification is keyed off a query-string-controllable organization, decoupling the verified secret from the actually-processed repository payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to HMAC-verify the request against by reading `repository_owner`, which is computed from `params.dig('repository', 'owner', 'login')`. This is the Rails action `params` (query string + body merged), not the raw JSON body that the request signature actually covers. The `create` action, however, re-parses `request.raw_post` independently into a local variable and dispatches it to handlers that resolve the target `Stack`/`Repository` from that body's own `repository.full_name` field. Because Rails merges query-string parameters over body parameters in `ActionDispatch::Http::Parameters#parameters` (query parameters take precedence on key collision), an attacker can supply a `repository[owner][login]=<attacker-org>` query parameter that changes which org's `webhook_secret` is used to verify the signature, while the signed/processed body content (and the resulting `Stack` lookup in `PushHandler`, `StatusHandler`, etc.) still refers to an unrelated, victim-owned repository.

### Finding Description
- Signature verification: `Shipit.github(organization: repository_owner)` picks a `GithubApp`/secret purely based on `repository_owner`, then calls `verify_webhook_signature(signature, request.raw_post)`. [1](#0-0) 
- `repository_owner` reads from `params`, the merged (GET+POST) parameter hash, not strictly from the signed raw body: [2](#0-1) 
- The actual event data acted on is parsed independently, straight from the raw POST body: [3](#0-2) 
- Handlers such as `PushHandler` resolve the impacted `Stack`s from `payload.dig('repository', 'full_name')` sourced from that same raw body, entirely independent of which organization's secret was used to authenticate the request: [4](#0-3) [5](#0-4) 
- The equality binding that should hold is: `organization whose secret authenticated the request == organization owning the repository the body causes state changes on`. Because `repository_owner` is derived from a value (`params`) that can diverge from `request.raw_post` via query-string precedence, this binding is not enforced — the attacker can make the two sides refer to different organizations.
- `verify_webhook_signature` itself is a plain HMAC-SHA1 comparison against whatever secret is looked up for the (attacker-influenced) org — if that org has no `webhook_secret` configured, verification is trivially bypassed (`return true unless webhook_secret`): [6](#0-5) 

### Impact Explanation
If an attacker knows (or controls) the `webhook_secret` of any org configured in the Shipit instance — or finds one configured without a secret — they can sign (or leave unsigned) a webhook body whose `repository.full_name`/`owner.login` actually references a *different*, victim-owned stack, then add a query-string override so `repository_owner` resolves to the org whose secret they control. The signature check passes against the wrong org's secret while the real handler dispatch (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, pull request handlers, etc.) still operates on the victim repository data embedded in the body. This enables forged `push`, `status`, `check_suite`, and `pull_request` events for arbitrary repositories, which can trigger `GithubSyncJob`, status/PR state mutation, or review-stack provisioning/merge flows for a repository the attacker does not control — an unauthorized state change analogous to an unauthorized deploy/merge trigger, satisfying the Critical bar of "unauthorized deploy/rollback/merge" via forged GitHub events with a broken authentication binding.

### Likelihood Explanation
Requires knowledge of at least one org's `webhook_secret` configured on the Shipit instance (or one org configured with no secret, which the docs/sample configs show as a real possibility, e.g. `webhook_secret: # nil`), plus knowledge of a victim stack's `repository.full_name`. No repository write access, session, or API token is needed — only unauthenticated HTTP access to the `/webhooks` endpoint, matching the "unprivileged attacker" scope of this exercise.

### Recommendation
Derive `repository_owner` (and any other value used to select the verification secret) strictly from the already-parsed raw JSON body (`request.raw_post`), not from the merged `params` accessor, so the value used to pick the verifying secret can never diverge from the value the signature actually covers and from the value handlers subsequently act upon. Alternatively, re-verify that the org resolved for signature purposes matches the org implied by the body used in `create` before dispatching to handlers.

### Proof of Concept
1. Instance has two orgs configured: `attacker-org` (webhook_secret known to attacker, or unset) and `victim-org` (webhook_secret unknown, owns the target Stack).
2. Attacker POSTs to `/webhooks?repository[owner][login]=attacker-org` with:
   - Header `X-Github-Event: push`
   - Body: `{"ref": "refs/heads/master", "after": "<forged-sha>", "repository": {"full_name": "victim-org/victim-repo", "owner": {"login": "victim-org"}}}`
   - `X-Hub-Signature` computed with `attacker-org`'s secret (or omitted if `attacker-org` has none).
3. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` (from the query string) and validates against `attacker-org`'s secret — passes.
4. `create` re-parses `request.raw_post`, dispatches to `PushHandler`, which looks up stacks for `victim-org/victim-repo` and calls `stack.sync_github(expected_head_sha: "<forged-sha>")`, affecting the victim's stack despite the attacker never possessing `victim-org`'s webhook secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
