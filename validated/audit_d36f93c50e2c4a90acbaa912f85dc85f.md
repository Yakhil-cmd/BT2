## Finding: Webhook signature verification is bound to the wrong field — organization used to select the signing secret is never bound to the repository the event handlers act on

### Title
Webhook signature verification authenticates the wrong entity, allowing cross-repository writes via mismatched `repository.owner.login` / `repository.full_name` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
This is the Shipit-engine analog of the reserve-sale vulnerability: a value that determines *what gets acted on* (`repository.full_name`, used to pick the target `Stack`/`Repository`) is never cross-checked against the value that determines *what gets authenticated* (`repository.owner.login`/`organization.login`, used to pick the GitHub App/secret that verifies the signature). Just as `_sellDsReserve` executed a swap without checking a value tied to the trade's actual effect, `WebhooksController#verify_signature` verifies a signature scoped to one organization while the `create` action lets the payload's own `repository.full_name` field decide which (potentially unrelated) repository/stack is mutated.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/secret to check the HMAC with, based on `repository_owner`: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`verify_webhook_signature` trivially returns `true` when no `webhook_secret` is configured for that organization — a state the setup docs explicitly describe as optional: [3](#0-2) 

Meanwhile, the actual event handlers ignore `repository_owner` entirely and derive the acted-upon repository purely from `repository.full_name` inside the same JSON body: [4](#0-3) 

This is used by every repository-scoped handler (push, pull_request opened/closed/labeled/unlabeled, etc.) to resolve the `Stack`/`Repository` object to mutate, e.g.: [5](#0-4) [6](#0-5) [7](#0-6) 

Nowhere is `repository.full_name`'s owner segment checked against `repository_owner` — the value the signature was actually verified against. The binding that should hold is:

```
organization authenticated (repository.owner.login → secret selection) == organization whose repository is written (repository.full_name → Stack/Repository lookup)
```

That equality is never enforced.

### Impact Explanation
Because the webhook secret is per-organization and documented as **optional** (`docs/setup.md`), and because `verify_webhook_signature` unconditionally passes when a secret is absent for the selected organization, any organization onboarded to a Shipit instance without a configured `webhook_secret` becomes a skeleton key for the entire multi-tenant deployment: an attacker can POST an arbitrary JSON body to `/webhooks` with `repository.owner.login` set to that unsecured org (satisfying `verify_signature`) while setting `repository.full_name` to `"victim-org/victim-repo"`. The handler pipeline will then act on the victim's `Stack`/`Repository` — archiving/unarchiving review stacks, provisioning new review stacks (which enqueues real deploy/provisioning tasks), or triggering `GithubSyncJob` for a repository the attacker has no relationship to. This is a cross-repository write crossing an authentication boundary the code believes it enforces, matching the "Critical – cross-repository writes / unauthorized deploy" impact category.

### Likelihood Explanation
Exploitability requires only that at least one organization configured on the Shipit instance lacks a `webhook_secret` — a state the project's own setup documentation presents as a normal, supported configuration choice, not an error. No `ApiClient` token, GitHub App private key, or prior webhook secret knowledge is needed for that path, satisfying the "unprivileged attacker" constraint.

### Recommendation
After parsing the payload, verify that the organization used to select the signing secret (`repository.owner.login` / `organization.login`) matches the owner segment of `repository.full_name` (or the resolved `Repository#owner`) before dispatching to handlers, and reject the webhook otherwise. Additionally, consider making `webhook_secret` mandatory for any organization to be onboarded, rather than optional, given `verify_webhook_signature` fully disables verification in its absence.

### Proof of Concept
1. Configure Shipit with two organizations: `attacker-org` (no `webhook_secret` set) and `victim-org` (any config, containing a real `Stack` for `victim-org/victim-repo`).
2. POST to `/webhooks` with header `X-Github-Event: pull_request` and body:
```json
{
  "action": "closed",
  "number": 1,
  "pull_request": { "...": "valid shape matching ClosedHandler params" },
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "sender": { "login": "attacker-org-bot" }
}
```
3. `verify_signature` calls `Shipit.github(organization: "attacker-org")`; since `attacker-org` has no `webhook_secret`, `verify_webhook_signature` returns `true` regardless of the `X-Hub-Signature` header sent (any value, even absent).
4. `create` dispatches to `PullRequest::ClosedHandler`, which resolves `Shipit::Repository.from_github_repo_name("victim-org/victim-repo")` and calls `review_stack.archive!` on the victim's real review stack — an unauthorized write to `victim-org`'s data performed under the guise of `attacker-org`'s (secret-less) authentication. [7](#0-6)

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
