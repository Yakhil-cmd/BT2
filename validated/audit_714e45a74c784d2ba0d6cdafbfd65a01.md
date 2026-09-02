### Title
Forged `pull_request` `edited` webhook bypasses signature check via no-secret org and cross-repo `full_name` mismatch, causing cross-tenant `PullRequest` mutation - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/org used to verify the HMAC signature solely from `repository.owner.login` in the untrusted request body, and `GitHubApp#verify_webhook_signature` auto-approves any request when that org has no configured `webhook_secret`. The actual repository the `EditedHandler` mutates is resolved independently from `repository.full_name`, so nothing binds the "verifying org" to the "mutated repository's org", letting an attacker impersonate one org to write into another org's `PullRequest` record.

### Finding Description
The broken invariant, stated as an equality that the code fails to enforce: `organization_that_verified_signature (params.repository.owner.login) == organization_that_owns_mutated_repository (owner of params.repository.full_name)`.

Trace:
1. `WebhooksController#verify_signature` computes `repository_owner` as `params.dig('repository','owner','login')` and fetches `Shipit.github(organization: repository_owner)`, then calls `verify_webhook_signature`: [1](#0-0) [2](#0-1) 
2. `GitHubApp#verify_webhook_signature` short-circuits to `true` whenever the selected org's `webhook_secret` is blank/nil — i.e., signature verification is a no-op for any org configured without a secret: [3](#0-2) 
3. Once verification passes, `WebhooksController#create` parses the raw body and dispatches it, unmodified, to all handlers for the `pull_request` event: [4](#0-3) 
4. `Shipit::Webhooks::Handlers::PullRequest::EditedHandler#process` resolves the repository to mutate using `params.repository.full_name` — a completely different field than the one used in step 1 — via `Shipit::Repository.from_github_repo_name`, then finds and updates the matching `PullRequest` row: [5](#0-4) 

Because `repository.owner.login` (used to pick the verifying `GitHubApp`) and `repository.full_name` (used to pick the mutated `Repository`/`PullRequest`) are independent, attacker-controlled JSON fields with no cross-validation, an attacker who knows of any organization in `Shipit.github_organizations` that has no `webhook_secret` configured can set `repository.owner.login` to that org (making `verify_webhook_signature` return `true` unconditionally, regardless of `X-Hub-Signature`) while setting `repository.full_name` to `"<victim-org>/<victim-repo>"`. The forged body then flows straight into `EditedHandler`, which updates the persisted `PullRequest` for the victim org's stack via `pull_request.update(github_pull_request: params.pull_request)`.

Existing guards do not prevent this: `drop_unhandled_event` only checks the event type exists a handler for it; `ExplicitParameters` schema on `EditedHandler` only validates types/presence of fields, not cross-field consistency between `repository.owner.login` and `repository.full_name` (the schema doesn't even require `repository.owner.login`); `GithubOrganizationUnknown` only fires when the org name in `repository.owner.login` isn't configured at all, not when it's configured without a secret.

### Impact Explanation
An attacker with no Shipit credentials can inject/overwrite fields of an arbitrary tracked `PullRequest` belonging to any other organization/repository configured in the same Shipit instance (title, state, additions/deletions, head sha/ref, assignees, labels, etc. — whatever `github_pull_request` stores), as long as one org in the multi-org config lacks a `webhook_secret`. This is a cross-tenant state manipulation where a request authenticated as (or rather, unauthenticated against) one org writes into another org's records, matching the "Critical: payload for one repository mutating another's stack/commit/task" category. It is repeatable against any stack/PR number combination and does not require any interaction with the real GitHub API.

### Likelihood Explanation
The precondition is that the Shipit deployment uses the multi-organization GitHub config (`Shipit.github_organizations` with per-org `secrets.github`) and at least one configured org has no `webhook_secret` set — a realistic/plausible misconfiguration, especially for demo/internal/dev orgs sharing a Shipit instance with production orgs. Given that, the attacker cost is a single unauthenticated `POST /webhooks` request with a crafted JSON body and correct `X-Github-Event: pull_request` header; no signature computation is even required. The attack is trivially repeatable and scriptable.

### Recommendation
Bind signature verification to the same repository/org that handlers act on: resolve the target `Repository` from `full_name` first, derive its organization, and verify the signature against that org's secret (not the attacker-supplied `owner.login`). Additionally, treat a missing `webhook_secret` as a configuration error to reject (or require) rather than silently trusting all requests, and/or cross-validate `repository.owner.login` against the parsed owner from `repository.full_name` before dispatching to handlers.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`-style, ActionDispatch::IntegrationTest):
1. Configure two orgs in `Shipit.stubs(:github_organizations).returns(['no-secret-org', 'victim-org'])`; stub `Shipit.github(organization: 'no-secret-org')` to return a `GitHubApp` built with `config: { webhook_secret: nil }`, and stub `Shipit.github(organization: 'victim-org')` with a real secret.
2. Create fixtures: a `victim-org/repo` `Repository`, its `Stack`, and a `PullRequest` with `number: 42` and some baseline `github_pull_request` (e.g., `title: "original"`).
3. Build the forged payload: `{ action: 'edited', number: 42, pull_request: { ..., title: "PWNED" }, repository: { owner: { login: 'no-secret-org' }, full_name: 'victim-org/repo' }, sender: { login: 'attacker' } }`.
4. `POST /webhooks` with header `X-Github-Event: pull_request` and an arbitrary/garbage `X-Hub-Signature` (e.g., `"sha1=deadbeef"`).
5. Assert response is `:ok` (verification passed despite bad signature, because `no-secret-org` has no secret).
6. Assert `pull_request.reload.github_pull_request['title'] == "PWNED"` — proving the payload nominally "verified" against `no-secret-org` mutated a `PullRequest` belonging to `victim-org`, i.e. `params.repository.owner.login ("no-secret-org") != owner_of(params.repository.full_name) ("victim-org")` yet the write succeeded, confirming the broken binding.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L41-65)
```ruby
          def process
            return unless respond_to_pull_request_edited?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end

          private

          def pull_request
            @pull_request ||= Shipit::PullRequest
                              .joins(:stack, stack: :repository)
                              .find_by(
                                number: params.number,
                                stacks: {
                                  repositories:
                                    {
                                      id: repository.id
                                    }
                                }
                              )
          end

          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
          end
```
