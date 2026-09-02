### Title
Cross-tenant PR label overwrite via organization/repository field decoupling in webhook signature verification - ([File: app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret using `repository.owner.login` (or `organization.login`) from the raw JSON body, but every handler—including `LabelCapturingHandler`—resolves the repository/stack to mutate using the *separate* `repository.full_name` field from that same unsigned body. When the selected organization has no `webhook_secret` configured, `GitHubApp#verify_webhook_signature` returns `true` unconditionally, so an attacker can pick that org for verification while pointing `repository.full_name` at an unrelated victim repository.

### Finding Description
The claimed binding is: `organization verifying HMAC (params.repository.owner.login) == organization owning the PullRequest whose labels are overwritten (owner of params.repository.full_name)`.

Trace:
- `WebhooksController#verify_signature` computes `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0) 
- `GitHubApp#verify_webhook_signature` short-circuits to `true` whenever the resolved app's `webhook_secret` is blank: `return true unless webhook_secret`. [2](#0-1) 
- The controller then dispatches the *entire raw body* to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. [3](#0-2) 
- `LabelCapturingHandler#repository` resolves the acted-upon repository from `params.repository.full_name`, a field never used during signature verification: `Shipit::Repository.from_github_repo_name(params.repository.full_name)`. [4](#0-3) 
- `stack` is looked up scoped to that repository's `review_stacks`, keyed only by `environment: "pr#{params.number}"`. [5](#0-4) [6](#0-5) 
- `capture_labels` then overwrites the resolved victim `PullRequest`'s labels using attacker-supplied names from the same body: `pull_request.update!(labels: params.pull_request.labels.map(&:name))`. [7](#0-6) 

Because `repository.owner.login` (used to pick the verifying `GitHubApp`) and `repository.full_name` (used to pick the mutated repository/stack) are two independent JSON fields inside one attacker-controlled, unsigned HTTP body, nothing forces them to refer to the same tenant. If Shipit has any configured organization without a `webhook_secret`, an attacker sets `repository.owner.login` to that org (satisfying `verify_signature` trivially) and `repository.full_name` to `victim-org/victim-repo` (an org that legitimately does have a secret and would otherwise reject the forged signature). Existing guards do not catch this: `drop_unhandled_event` only checks the event type header exists as a handled event, and `verify_signature`'s only real check (HMAC comparison) is bypassed entirely for secret-less orgs by design (`return true unless webhook_secret`). There is no cross-check anywhere that `repository.owner.login == repository.full_name.split('/').first`.

### Impact Explanation
An attacker who controls, or can name, a Shipit-configured organization lacking a `webhook_secret` can forge arbitrary `pull_request` webhooks that mutate PR label state on any other repository/organization onboarded to the same Shipit instance, as long as an active `ReviewStack`/`PullRequest` exists for the targeted PR number. This is a cross-tenant data-corruption primitive: labels drive `LabeledHandler`/`UnlabeledHandler` provisioning_behavior gates (`allow_with_label`/`prevent_with_label`), so corrupting label state can indirectly influence archive/unarchive/provisioning decisions for stacks the attacker does not own. This matches the "payload for one repository mutating another's stack" Critical category. It is repeatable against any PR number of any repository with an existing active review stack, for every request.

### Likelihood Explanation
This requires: (1) Shipit to have at least one organization configured without a `webhook_secret` (a plausible, code-supported, non-default-enforced configuration state — `webhook_secret` is optional per `GitHubApp#initialize`), and (2) a pre-existing active `ReviewStack`/`PullRequest` in the victim repo matching the crafted PR number. Given those, the attacker needs no credentials, GitHub App keys, or team membership — only the ability to POST arbitrary JSON to `/webhooks`. Cost is a single unauthenticated HTTP request, fully repeatable.

### Recommendation
Bind signature verification and repository resolution to the same field. Either (a) require `params.repository.owner.login` (or `organization.login`) to equal the owner segment parsed from `params.repository.full_name` before dispatching to handlers, rejecting mismatches with 422; or (b) resolve the repository/organization used for signature verification directly from `repository.full_name` rather than a separate `repository.owner.login` field; or (c) disallow the "no webhook_secret configured" bypass (`return true unless webhook_secret`) for organizations that have any repositories/stacks configured, forcing every onboarded org to require a secret.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/pull_request/label_capturing_handler_test.rb`, hypothetical—file itself is out of scope but describes the required assertions):
1. Configure two orgs in `Shipit.app`: `attacker-org` with no `webhook_secret`, and `victim-org` with a `webhook_secret` set.
2. Create `victim_repo = Shipit::Repository.create!(owner: 'victim-org', name: 'victim-repo')`, a `ReviewStack` with `environment: 'pr42'` under `victim_repo`, and its associated `pull_request` with `labels: ['legit']`.
3. Build a payload body where `repository.owner.login == 'attacker-org'`, `repository.full_name == 'victim-org/victim-repo'`, `number == 42`, `action == 'labeled'`, and `pull_request.labels == [{name: 'attacker-label'}]`.
4. Assert `Shipit.github(organization: 'attacker-org').verify_webhook_signature(anything, body_json)` returns `true` (no secret needed) — confirming the org used for HMAC differs from the org owning the mutated record.
5. Invoke `LabelCapturingHandler.call(parsed_payload)`.
6. Assert `pull_request.reload.labels == ['attacker-label']`, proving the victim org's PR labels were overwritten despite verification being performed against the unrelated, secret-less `attacker-org`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-101)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-114)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L15-17)
```ruby
          def stack
            @stack ||= scope.find_by(environment:)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L96-98)
```ruby
          def environment
            "pr#{params.number}"
          end
```
