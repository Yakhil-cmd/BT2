### Title
Webhook signature is verified against the payload's `repository.owner.login`, but handlers act on the (unrelated) `repository.full_name` field, allowing any configured GitHub organization's webhook secret to forge writes against any other organization's stacks - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks which GitHub App (and thus which `webhook_secret`) authenticates an inbound webhook based on `repository.owner.login` (or `organization.login`) in the JSON body. Once the HMAC is accepted, the entire raw payload — including a completely separate field, `repository.full_name` — is handed to the event handlers, which use `repository.full_name` to look up the `Repository`/`Stack` to mutate. In a multi-organization Shipit install (the officially documented "Using Multiple Github Applications" configuration), these two fields are never cross-checked against each other. This mirrors the StRSR bug class: the binding used to establish trust (`stakeRSR`/`totalStakes` invariant in the referenced report, here "organization authenticated") diverges from the value the mutating logic actually operates on ("repository that is written"), because the code assumes they always match a single tenant.

### Finding Description
- Signature verification: `Shipit.github(organization: repository_owner)` where
  `repository_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) [2](#0-1) 
- This organization key is used purely to select which `GitHubApp` config's `webhook_secret` verifies the HMAC signature: `github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)`. Multi-org support is a first-class, documented feature (`Shipit.github(organization:)`, `github_app_config`), meaning a single Shipit instance can host many independently-trusted organizations, each with its own app/secret. [3](#0-2) 
- After signature verification succeeds, `params = JSON.parse(request.raw_post)` (the *entire* payload, not just the fields used for verification) is dispatched unchanged to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. [4](#0-3) 
- The base `Handler` class resolves the target repository/stacks from a *different* payload field, `repository.full_name`, with no relation to `repository.owner.login`/`organization.login` used for authentication: [5](#0-4) 
- Every concrete handler (push, pull_request opened/closed/reopened/labeled/unlabeled/edited, etc.) follows this same pattern, resolving `Repository.from_github_repo_name(params.repository.full_name)` and then mutating state on whatever stack that repository owns, e.g. archiving/unarchiving/deprovisioning a review stack: [6](#0-5) [7](#0-6) [8](#0-7) 

**Binding broken (as equality):**
`organization_that_authenticated(repository.owner.login) == organization_owning(repository.full_name)`

The code implicitly assumes this always holds (single-tenant deployments, or a 1:1 mapping between the org in `repository.owner.login` and the repo in `repository.full_name`), but nothing enforces it. In the documented multi-org configuration, an attacker who legitimately controls one org's webhook secret (e.g., they administer "OrgA"'s GitHub App installed on the shared Shipit instance) can send a webhook whose `repository.owner.login`/`organization.login` = `"OrgA"` (satisfying `verify_signature`) while `repository.full_name` = `"OrgB/some-repo"` (a repository belonging to an entirely different, unrelated organization hosted on the same Shipit instance). The signature check passes using OrgA's secret, but the handler acts on OrgB's stack.

### Impact Explanation
This crosses an organizational trust boundary that Shipit explicitly models as isolated (each org has its own GitHub App/webhook secret specifically so that one org cannot act on another's repositories). Concretely, `PullRequest::ClosedHandler#process` calls `review_stack.archive!`, which deprovisions and archives a review stack (running the stack's deprovisioning/rollback steps) for a repository the forging org has no legitimate relationship with; `OpenedHandler`/`ReopenedHandler` can create/unarchive review stacks (provisioning them, i.e. triggering deploy-like actions) for another org's repo; `PushHandler` can force a resync (`GithubSyncJob`) of another org's stack. This is a cross-organization, cross-repository unauthorized action — matching the "cross-repository writes" / "unauthorized deploy, rollback" impact bar, achievable by any party who holds a webhook secret for just one of the many organizations configured on a shared instance, not by the Shipit-instance operator.

### Likelihood Explanation
Requires (a) a Shipit deployment configured with the documented multi-organization `github:` config (each org has its own app/secret) — an officially supported and documented setup — and (b) the attacker being a legitimate holder of one organization's webhook secret (e.g., an org owner/admin of one of the several tenant organizations) who is not supposed to have any access to other tenants' repositories/stacks. No leaked or privileged Shipit credentials are needed; only crafting an HTTP POST to `/webhooks` with a validly-signed-for-OrgA body whose `repository.full_name` points at another org's repo.

### Recommendation
After verifying the signature for `repository_owner`, additionally verify that the repository named in `repository.full_name` (or `pull_request.base.repo.full_name`, etc.) actually belongs to that same `repository_owner`/`organization`, and reject (422) the webhook otherwise. Alternatively, resolve the target `Repository` model and confirm its configured GitHub organization/app matches the one whose secret validated the signature before dispatching to handlers.

### Proof of Concept
Given a Shipit instance configured per `docs/setup.md`'s "Using Multiple Github Applications" section with two orgs, `OrgA` and `OrgB`, each having their own installed GitHub App and `webhook_secret`:

1. Attacker (who administers `OrgA`'s GitHub App) crafts a `pull_request` `closed` webhook payload:
```json
{
  "action": "closed",
  "number": 5,
  "pull_request": { "...": "..." },
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" },
  "sender": { "login": "attacker" }
}
```
2. Attacker signs the raw body with `OrgA`'s `webhook_secret` and sends it to `/webhooks` with header `X-Github-Event: pull_request`.
3. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")` and validates successfully against `OrgA`'s secret [1](#0-0) .
4. `PullRequest::ClosedHandler` resolves the repository via `params.repository.full_name` = `"OrgB/victim-repo"` [9](#0-8)  and calls `review_stack.archive!`, deprovisioning/archiving a review stack that belongs to `OrgB`, an organization the attacker has no legitimate authority over.

Note: I could not execute this against a running instance from this environment (no filesystem/terminal access here); the trace above is based on static analysis of the cited files. A background Devin session with repo/terminal access could write an integration test (similar to `test/controllers/webhooks_controller_test.rb`) using `test/dummy/config/secrets_double_github_app.yml` to concretely demonstrate cross-org state mutation.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
