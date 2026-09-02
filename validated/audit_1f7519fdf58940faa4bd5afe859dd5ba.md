This confirms the code path is real and matches the claim exactly.

### Title
Blank `webhook_secret` causes `GitHubApp#verify_webhook_signature` to accept unsigned webhooks, allowing attacker-controlled `repository.full_name` to route to any stack - (File: lib/shipit/github_app.rb, app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/handler.rb)

### Summary
`GitHubApp#verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank, so `WebhooksController#verify_signature` never rejects the request. Since `Handler#repository_name` is taken verbatim from the unauthenticated payload's `repository.full_name`, an attacker who knows (or guesses) that at least one configured GitHub org/app has no `webhook_secret` can forge webhook events naming any victim repository and trigger handler side effects (job enqueue, status/check-run writes) on that repository's stacks.

### Finding Description
The broken binding: `verified == (bytes signed by an org's real webhook_secret)` is claimed to hold, but in fact when `webhook_secret.blank?`, `verified == true` for **any** bytes, with no relation to the sender's identity.

Code path:
- [1](#0-0) : `verify_webhook_signature` returns `true` unless `webhook_secret` is present — i.e. `return true unless webhook_secret`.
- [2](#0-1)  calls this per `repository_owner` (`params.dig('repository','owner','login')`, itself attacker-supplied in the JSON body) and only `head(422)` if `verified` is false — when it's `true`, processing continues.
- [3](#0-2)  then dispatches `params` straight into `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`.
- [4](#0-3) : `repository_name` reads `payload.dig('repository', 'full_name')` directly, and `stacks` resolves `Repository.from_github_repo_name(repository_name)&.stacks`, both fully attacker-controlled with no cross-check against which org/app actually verified (or failed to verify) the request.

Root cause: signature verification is a per-organization opt-in gated by whether an operator configured `webhook_secret` for that org (see `docs/setup.md` and `config/secrets.development.example.yml`, where `webhook_secret:` is commonly left blank), and the "no secret configured" case is treated as "trust unconditionally" rather than "reject." Combined with the fact that `repository_owner`/`repository_name` used to pick *which* org's config governs verification are both taken from the same untrusted payload, an attacker can pick a victim repository under a *different*, secured org while ensuring the `owner.login` used for verification resolves to the org with the blank secret — or simply target any org known to have no secret configured, if such an org's real repositories exist alongside others in the same Shipit instance.

Exploit flow: attacker POSTs to `/webhooks` with `X-Github-Event: status` (or `push`, `check_suite`), payload `repository.full_name` = victim's real tracked repo, `repository.owner.login` = the org whose app has `webhook_secret` blank. `verify_signature` calls `Shipit.github(organization: <that org>)`, gets `verified = true` unconditionally, and the handler processes the forged event against the real victim stack.

Existing guards fail because: `drop_unhandled_event` only checks event type is registered, not authenticity; `verify_signature`'s only failure mode is `GithubOrganizationUnknown` (unknown org name) or signature mismatch when a secret *is* configured — neither applies here since the org name is valid and no secret exists to mismatch against.

### Impact Explanation
An attacker can enqueue `GithubSyncJob`, mutate `Commit` statuses, or trigger `RefreshCheckRunsJob` against any stack tracked by Shipit, without possessing any secret, purely by naming `repository.full_name` in a POST to `/webhooks`, provided any configured org in `Shipit.github_apps`/`secrets.github` has a blank `webhook_secret`. This is a payload for one (attacker-named) repository mutating another's stack/commit/task state without authentication — matching the Critical category (authentication bypass / cross-tenant mutation). Blast radius spans every stack whose repository is reachable via `Repository.from_github_repo_name`, i.e. potentially the entire instance, and is fully repeatable per request.

### Likelihood Explanation
Requires only that the deployed Shipit instance has at least one GitHub App/org configuration with `webhook_secret` unset — a state the project's own example configs (`config/secrets.development.example.yml`, `config/secrets.development.shopify.yml`, `test/dummy/config/secrets_double_github_app.yml`) show as a normal/documented default, and which the audit rules explicitly state is in scope regardless of how common it is. No credentials, sessions, or GitHub-side secrets are needed; the attacker only needs network access to POST JSON to `/webhooks` with correct headers. Cost is trivial and the attack is fully repeatable.

### Recommendation
Treat a blank `webhook_secret` as "signature verification impossible" and reject (fail closed) rather than "signature verification unnecessary" (fail open) in `GitHubApp#verify_webhook_signature`, or require operators to configure a webhook secret before the webhooks endpoint accepts any traffic for that org. At minimum, log/alert loudly and consider disabling automatic processing for orgs without a configured secret.

### Proof of Concept
In `test/controllers/webhooks_controller_test.rb` style (illustrative; not to be placed under `test/` per audit scope, but describing the minitest plan):
1. Configure `Shipit.stubs(:github).with(organization: 'attacker-org').returns(GitHubApp.new('attacker-org', { webhook_secret: nil, ... }))`.
2. Build a `status` (or `push`) payload with `repository.owner.login = 'attacker-org'` and `repository.full_name` set to an existing victim stack's real repo (e.g. `shipit_stacks(:shipit).repository.github_repo_name`).
3. POST to `:create` with `X-Github-Event: status` and no valid `X-Hub-Signature` (or an arbitrary bogus one).
4. Assert `assert_difference('commit.statuses.count', 1) { post :create, body: payload.to_json, as: :json }` succeeds and `assert_response :ok`, proving the victim stack's commit was mutated by a request that never presented a valid signature for that org and had no relationship to the victim org's real secret.

### Citations

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
