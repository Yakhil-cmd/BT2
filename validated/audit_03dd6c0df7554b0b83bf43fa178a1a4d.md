### Title
Repository lookup binds only on `repository.full_name`, not on the org whose `webhook_secret` verified the signature, enabling cross-tenant stack provisioning - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/repository.rb], [File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC key using `repository_owner`, which is read straight from the attacker-controlled JSON body (`params.dig('repository','owner','login')`), while every handler (e.g. `OpenedHandler`) resolves the target `Repository` from a different, independently attacker-controlled field of the same body: `repository.full_name`. Nothing cross-checks that these two fields refer to the same organization, so on a multi-org Shipit instance an attacker who legitimately owns one configured org can sign an arbitrary body with their own `webhook_secret` while pointing `repository.full_name` at a different org's repository.

### Finding Description
Binding claimed: `org(webhook_secret that verified the request) == org(Repository row that provision?/ReviewStackAdapter mutate)`.

Trace:
- `WebhooksController#verify_signature` computes the key-selection organization as `repository_owner`: [1](#0-0) , and uses it only to pick which `GitHubApp`/`webhook_secret` to verify the raw body against: [2](#0-1) .
- The HMAC is computed over the entire raw POST body with that org's secret: [3](#0-2) . This only proves the attacker knows the secret for whatever org `repository.owner.login` says — it does not prove anything about `repository.full_name`.
- Downstream, `OpenedHandler#repository` (and every other pull_request handler / `Handler#stacks`) resolves the target repository purely from `repository.full_name`, ignoring `repository.owner.login` entirely: [4](#0-3) , [5](#0-4) .
- `Repository.from_github_repo_name` performs a strict `owner`/`name` lookup on whatever string is in `full_name`, with no relation back to `repository_owner`: [6](#0-5) .

Because `repository.owner.login` and `repository.full_name` are two independent fields inside the same signed JSON blob, an attacker who owns an org configured in this Shipit instance (`evilcorp`, per the documented multi-org config schema in `config/secrets.development.example.yml`) can set `repository.owner.login = "evilcorp"` (so `verify_signature` picks and validates against evilcorp's own `webhook_secret`, which the attacker knows) while setting `repository.full_name = "shopify/shipit-engine"`. The signature check passes, `drop_unhandled_event`/`ExplicitParameters` do not enforce owner consistency (the schema only `requires :full_name, String`, see e.g. [7](#0-6) ), and `OpenedHandler#process` runs against the real `shopify/shipit-engine` `Repository` row, evaluating `provision?` and calling `ReviewStackAdapter.find_or_create!` on it: [8](#0-7) .

Existing guards do not close this gap: `verify_signature`'s only job is picking/validating a secret by `repository_owner`, it never compares that value to `full_name`'s owner segment; `ExplicitParameters` only type-checks presence of `full_name`; `Repository` model validations only constrain character set/length of `owner`/`name`, not cross-field consistency with the signing org.

### Impact Explanation
If exploited, an attacker-crafted `pull_request` "opened" webhook — signed with credentials the attacker legitimately possesses for their own org — causes `OpenedHandler` to operate on a `Repository`/`Stack` belonging to an entirely different tenant (e.g. `shopify/shipit-engine`), potentially triggering `ReviewStackAdapter.find_or_create!` to provision a review stack (and subsequent CI/deploy tasks) using attacker-supplied PR data (`head.sha`, `head.ref`, labels, etc.) for a repository the attacker does not control. This is a cross-tenant stack mutation/provisioning primitive, matching the Critical category "a payload for one repository mutating another's stack." The same divergence affects every other pull_request handler that resolves `repository` via `from_github_repo_name(params.repository.full_name)` (closed, labeled, unlabeled, reopened, label_capturing), so the blast radius covers the full PR-driven review-stack lifecycle for any repository configured in the same Shipit instance, repeatable for any target repo/org pair the attacker can guess or enumerate.

### Likelihood Explanation
Requires: (1) the Shipit deployment configured for multiple GitHub organizations (per-org `webhook_secret`, as documented), and (2) the attacker being a legitimate owner/admin of at least one org onboarded to that same Shipit instance (so they know that org's `webhook_secret`) — both realistic in a multi-tenant Shipit deployment, which is an explicitly supported and documented configuration. No GitHub App private key, session, or API token is needed; the attacker only crafts a JSON body and computes one HMAC-SHA1 with a secret they already hold, then POSTs directly to `/webhooks`. This is trivially repeatable and scriptable.

### Recommendation
Enforce that the organization used to select/verify the webhook secret matches the organization encoded in every repository-bearing field the handlers subsequently trust. Concretely, in `WebhooksController#verify_signature` (or in `Handler#initialize`), after determining the verifying org, assert that `params.dig('repository','full_name')&.split('/')&.first&.downcase == repository_owner&.downcase` (and similarly for `organization.login` fallback), rejecting with `422` on mismatch before any handler runs. Alternatively, derive the `Repository` lookup key from `repository_owner` (the value actually bound to the verified secret) rather than from `full_name`, or require the loaded `Repository#owner` to equal `repository_owner` before calling `provision?`/`ReviewStackAdapter`.

### Proof of Concept
Minitest under `test/controllers/webhooks_controller_test.rb` (adjusting for the two-org config fixture):
1. Configure `Shipit.github` with two orgs, `evilcorp` (secret `S1`) and `shopify` (secret `S2`), matching the documented multi-org schema.
2. Create `shipit_repositories(:shopify_shipit_engine)` owned by `shopify`, with `provisioning_behavior_allow_all`.
3. Build a `pull_request` "opened" payload where `repository.owner.login = "evilcorp"` and `repository.full_name = "shopify/shipit-engine"`.
4. Sign the raw body with `S1` (evilcorp's secret) and set `X-Hub-Signature` accordingly.
5. POST to `/webhooks` and assert:
   - `Shipit.github(organization: 'evilcorp').verify_webhook_signature(sig, body)` returns `true` (attacker's own secret matches — request is NOT rejected with 422), demonstrating LHS = `evilcorp`.
   - `Shipit::Repository.from_github_repo_name('shopify/shipit-engine')` returns the real `shopify` repository row, demonstrating RHS = `shopify`.
   - `assert_difference('Shipit::ReviewStack.count', 1) { post :create, body:, as: :json }` — showing `OpenedHandler#process` ran and mutated `shopify`'s repository despite the request only being authenticated for `evilcorp`.
6. After applying the recommended owner-consistency check, re-run the same request and assert `assert_response :unprocessable_entity` and `assert_no_difference('Shipit::ReviewStack.count') { ... }`, confirming `OpenedHandler#process` never executes.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
