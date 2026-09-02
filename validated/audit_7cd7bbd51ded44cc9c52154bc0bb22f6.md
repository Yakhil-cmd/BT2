### Title
Webhook signature verified against attacker-selected `organization.login`, but `LabelCapturingHandler` mutates the repository named by an independent `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which `GitHubApp` (and thus which `webhook_secret`) authenticates a webhook using `repository_owner`, which falls back to `params.dig('organization','login')` whenever `repository.owner.login` is absent. `LabelCapturingHandler`, however, determines which `Repository`/`Stack` to mutate purely from `params.repository.full_name`, an independent field with no cross-check against the organization that authenticated the request.

### Finding Description
The broken binding is the implicit assumption:
`repository_owner` (used to pick the verifying secret) `== owner(params.repository.full_name)` (used to pick the mutated repository).

Trace:
- `repository_owner` is computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) .
- `verify_signature` uses this value to select the `GitHubApp` config: `Shipit.github(organization: repository_owner)`, then calls `verify_webhook_signature` [2](#0-1) .
- `GitHubApp#verify_webhook_signature` is scoped per organization config (`@webhook_secret = @config[:webhook_secret].presence`), and `Shipit.github` resolves a distinct `GitHubApp`/secret per organization key in `secrets.github` via `github_app_config` [3](#0-2) [4](#0-3) .
- The handler, meanwhile, resolves the affected repository solely from `params.repository.full_name`: `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [5](#0-4) , and persists attacker-controlled label names onto that repository's stack's `PullRequest` via `capture_labels` [6](#0-5) .

An attacker who controls (or targets a misconfigured, secret-less) organization entry in a multi-tenant `secrets.github` config can send a request where `organization.login` = that org (satisfying/bypassing `verify_webhook_signature`, which returns `true` unconditionally when `webhook_secret` is blank for the selected org: `return true unless webhook_secret` [7](#0-6) ), while `repository.owner.login` is omitted (forcing the `organization.login` fallback) and `repository.full_name` names a victim repository belonging to an entirely different, unrelated organization/stack. Because `LabelCapturingHandler`'s `ExplicitParameters` schema only requires `repository.full_name` (not `repository.owner.login`) [8](#0-7) , this payload passes schema validation and the divergence is never checked anywhere in the pipeline: `verify_signature`, `drop_unhandled_event`, and the handler's own parameter parsing all operate on the two fields independently, with no equality check tying the authenticated organization to the resolved repository.

### Impact Explanation
If exploitable, an attacker who authenticates against one (weakly-secured or attacker-owned) organization's webhook secret can write attacker-controlled label names onto a `PullRequest`/`ReviewStack` belonging to a completely different tenant's stack, matching the Critical category "a payload for one repository mutating another's stack." Combined with a `bot_login`-configured stack where labels feed into `ReviewStack#env` and trigger auto-deploys under the bot identity, this could escalate to unauthorized deploy/rollback execution as the bot user. The blast radius is bounded to installations that configure multiple GitHub organizations (or an organization lacking `webhook_secret`) in `secrets.github`; it is repeatable per request against any repository/stack reachable via `Repository.from_github_repo_name`.

### Likelihood Explanation
This requires a specific precondition: the Shipit deployment must be multi-tenant (multiple `organization` entries under `secrets.github`) with at least one organization either controlled by the attacker or misconfigured without a `webhook_secret`. In a single-organization deployment (the common case, where `github_default_organization` is `nil` and the single `secrets.github` config is always used regardless of `organization.login`) [9](#0-8) , this fallback has no effect because the same secret validates every request regardless of `repository_owner`. I was not able to fully verify, within the available tool budget, the downstream chain from captured labels to `ReviewStack#env` uppercasing and auto-triggered bot deploys referenced in the question; only the label-persistence step (`capture_labels`) was directly confirmed.

### Recommendation
Cross-check that `repository.owner.login` (or the resolved `Repository#organization`) matches the organization used to select the verifying `GitHubApp`/`webhook_secret` before dispatching to handlers; reject requests where `repository.full_name`'s owner differs from `repository_owner`. Do not allow `LabelCapturingHandler` (and sibling PR handlers) to resolve a repository independently of the value used for signature verification.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`):
1. Configure `Shipit.stubs(:secrets)` (or credentials fixture) with two orgs: `victim-org` (with a `webhook_secret`) and `attacker-org` (no `webhook_secret`, i.e. omitted).
2. Create a victim stack/repository under `victim-org/repo` with `bot_login` configured, and an active `PullRequest` on its review stack.
3. Build a `pull_request` payload with `action: 'unlabeled'`, `repository: { full_name: 'victim-org/repo' }` (no `owner.login`), top-level `organization: { login: 'attacker-org' }`, and `labels: [{ name: 'DEPLOY_OVERRIDE' }]`.
4. POST to `/webhooks` with `X-Github-Event: pull_request` and any/no valid signature (since `attacker-org` has no secret, `verify_webhook_signature` returns `true`).
5. Assert: `response.status == 200`, and `victim` stack's `PullRequest#labels` was updated to `['DEPLOY_OVERRIDE']`, proving `repository_owner` (`attacker-org`, used for auth) diverged from `params.repository.full_name`'s owner (`victim-org`, used for mutation) while the write still succeeded.

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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-114)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end
```
