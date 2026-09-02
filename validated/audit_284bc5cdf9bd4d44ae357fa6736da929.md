### Title
Webhook signature check verifies `repository.owner.login`'s org while the pull_request handlers mutate a stack looked up from the independently-controlled `repository.full_name` field, allowing cross-tenant `ReviewStack` creation with an attacker-controlled `branch` - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to verify the HMAC using `repository_owner`, which is read from `params.dig('repository','owner','login')` in the raw, attacker-supplied JSON body. `ReopenedHandler#repository` independently resolves the target `Shipit::Repository` using `params.repository.full_name`, a separate field from the same body that is never cross-checked against `owner.login`. Because both fields are entirely attacker-controlled in the raw POST body, an attacker who can produce a valid signature for any org configured in Shipit (e.g., their own onboarded org) can name a completely different victim org/repo in `full_name`, causing `ReviewStack.create!` to be invoked under the victim's `Repository` scope with an attacker-chosen `branch`.

### Finding Description
The claimed-but-unenforced binding is: `repository_owner (used to select the verifying secret) == organization(params.repository.full_name) (used to select the mutated Repository)`.

Trace:
- `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` against the raw POST body. [1](#0-0) [2](#0-1) 
- If verification succeeds, `create` dispatches the same raw JSON body to handlers. [3](#0-2) 
- `ReopenedHandler`'s `ExplicitParameters` schema only requires `repository.full_name` — it never requires or validates `repository.owner.login` — so nothing ties the two fields together at the schema layer. [4](#0-3) 
- `ReopenedHandler#repository` resolves the target `Repository` purely from `params.repository.full_name`, independent of whatever value was used as `repository_owner` during signature verification. [5](#0-4) 
- `process` then unarchives (and, if no existing stack, creates) a `ReviewStack` scoped to that resolved `repository.review_stacks`, gated only on that repository's own `provisioning_behavior_allow_all?`/label settings — none of which reference the signing org. [6](#0-5) [7](#0-6) [8](#0-7) 

Exploit flow: attacker crafts a raw JSON body where `repository.owner.login` = an org for which a valid HMAC secret is known to them (this is only required to be *some* org configured in Shipit's github app config — plausible in any multi-tenant Shipit deployment where the attacker legitimately administers one onboarded org and thus knows its own configured `webhook_secret`), while `repository.full_name` names an unrelated victim org/repo with `review_stacks_enabled` and `provisioning_behavior_allow_all?` true. They sign the raw body with the known secret and POST it to `/webhooks` with `X-Github-Event: pull_request`. `verify_signature` passes (it validates against the attacker's own org's secret, matching `repository.owner.login`), but the handler acts on the victim repository named in `full_name`. Since no `ReviewStack` exists yet for the referenced PR number, `unarchive!`'s fallback constructs a new stack via `create!`, using `branch: params.pull_request.head.ref`, which is fully attacker-supplied and unchecked against any real GitHub state, then queues it for provisioning under the victim's `Repository`.

None of the listed guards prevent this: `drop_unhandled_event` only checks the event type exists a handler for it; the `ExplicitParameters` schema for this handler validates structure/types only, not cross-field organization consistency; `verify_signature`'s only check is HMAC validity against whichever org `repository.owner.login` names, with no re-validation that this org matches `repository.full_name`'s org later used by the handler.

### Impact Explanation
A record (a `ReviewStack`, and the associated provisioning task through `Shipit::ReviewStackProvisioningQueue`) is created and queued under a victim organization's `Repository` as a direct result of a payload the attacker authenticated only under their own, unrelated org's secret. The `branch` value flowing into stack provisioning is attacker-controlled and unchecked, which downstream is used by git/`Command` operations during provisioning (checkout of that branch, running CI-equivalent hooks) using the victim's GitHub credentials/tokens. This is a cross-tenant mutation: "a payload for one repository mutating another's stack," matching the Critical impact category. It is repeatable against any victim repository configured with `review_stacks_enabled` + `allow_all` (or matching label rules) provisioning, for any PR number that doesn't already have a stack.

### Likelihood Explanation
Preconditions: the attacker must know a valid `webhook_secret` for at least one org configured in this Shipit instance's GitHub App config — practically their own onboarded org in a multi-tenant deployment — and the victim repository must have `review_stacks_enabled` with `provisioning_behavior_allow_all?` (or satisfy the label-based provisioning rule). No Shipit session, API token, or victim secret is required. Given these are realistic self-service configuration states in a multi-tenant Shipit deployment (per the audit's stated preconditions), the attack is cheap (a single crafted signed HTTP POST) and fully repeatable against any victim repo/PR-number combination.

### Recommendation
In `WebhooksController#verify_signature` (or in each handler), enforce that the organization derived from `repository.owner.login` (used to select the verifying secret) matches the organization portion of `repository.full_name` (used to resolve the target `Shipit::Repository`) before any handler is invoked; reject the webhook with 422 on mismatch.

### Proof of Concept
Add a minitest to `test/controllers/webhooks_controller_test.rb` / `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb`:
1. Create two `Repository` records: `attacker_org/attacker_repo` (with a configured `webhook_secret` known to the test, matching what would be attacker-known) and `victim_org/victim_repo` with `review_stacks_enabled: true` and `provisioning_behavior_allow_all?` true, no existing `ReviewStack` for PR #1.
2. Build a raw JSON payload with `action: 'reopened'`, `pull_request.head.ref: 'attacker-controlled-branch'`, `repository.owner.login: 'attacker_org'`, `repository.full_name: 'victim_org/victim_repo'`.
3. Sign the raw body with `attacker_org`'s webhook secret and POST to `/webhooks` with the correct `X-Hub-Signature` and `X-Github-Event: pull_request` headers.
4. Assert response is `:ok` (signature check passes for `attacker_org`).
5. Assert `Shipit::ReviewStack.where(repository: victim_repo, pull_request_number: 1).first` exists with `branch == 'attacker-controlled-branch'` — demonstrating that `repository_owner == 'attacker_org'` (verified) diverges from the actual mutated repository `'victim_org/victim_repo'`, and that the equality assumed by the design (`repository_owner` == organization of the mutated repo) is broken.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L55-59)
```ruby
          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L70-75)
```ruby
          def unarchive?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```
