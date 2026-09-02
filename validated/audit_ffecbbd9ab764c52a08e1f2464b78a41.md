### Title
Webhook signature is verified against the org derived from `repository.owner.login`, but every handler acts on the separate, unauthenticated `repository.full_name` field, allowing cross-organization stack writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-organization Shipit deployment (`config/secrets.yml` `github:` keyed by organization), `WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, taken from the still-unverified JSON body (`repository.owner.login`, or `organization.login`). Every webhook `Handler` (push, pull_request opened/closed/labeled/etc.) instead resolves the actual target `Stack`/`Repository` using a *different* field of that same body: `repository.full_name`, via `Repository.from_github_repo_name`. Nothing binds these two fields together. An attacker who legitimately controls one configured organization's webhook secret (e.g., because they administer their own GitHub org that has the Shipit GitHub App installed) can craft a payload where `repository.owner.login` = their own org (so signature verification passes using their own secret) but `repository.full_name` = `"other-org/other-repo"`, causing Shipit to act on a stack belonging to a completely different, unrelated organization/repository that they have no legitimate access to.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` computes: [1](#0-0) 
using `repository_owner`, which is read directly out of the raw, unauthenticated request body: [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization config (including a distinct `webhook_secret`) when Shipit is configured for multiple GitHub organizations: [3](#0-2) 

Once the signature check passes (using the secret for whatever org `repository.owner.login` claims to be), `WebhooksController#create` hands the entire parsed body to the registered handlers: [4](#0-3) 

But the base `Handler` class - and every concrete handler (`PushHandler`, `PullRequest::OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `UnlabeledHandler`, `AssignedHandler`, `EditedHandler`, `LabelCapturingHandler`, `ReviewStackAdapter`) - resolves the target repository/stack from a *different* JSON field, `repository.full_name`, not `repository.owner.login`: [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

`Repository.from_github_repo_name` simply splits `"owner/name"` and does a database lookup with no cross-check against the organization used to verify the signature: [9](#0-8) 

The binding that should hold is: `organization used to validate HMAC signature == organization whose repository/stack is acted upon`. The code breaks this equality — the two are read from independent, attacker-controllable fields inside the same JSON body that only needs to be *internally consistent enough* to pass HMAC verification with the key selected by one of those fields. The signature covers the raw bytes, but it does not enforce that `repository.full_name`'s owner matches `repository.owner.login`/`organization.login`.

### Impact Explanation
This is a cross-repository/cross-organization write ("Critical" category — "cross-repository writes"). Any organization admin who has legitimately installed the Shipit GitHub App on their own org (and thus knows/controls that org's `webhook_secret`, which is not a Shipit-internal secret — it is set by the org admin during GitHub App setup) can forge signed webhook deliveries against *any other organization's* stacks tracked by the same Shipit instance:
- `PushHandler` can trigger `stack.sync_github(expected_head_sha: ...)` for a foreign stack.
- `PullRequest::ClosedHandler` / `LabeledHandler` / `UnlabeledHandler` can call `review_stack.archive!` / `stack.unarchive!` on a foreign organization's review stacks.
- `AssignedHandler` / `EditedHandler` / `LabelCapturingHandler` can overwrite `PullRequest#github_pull_request` and captured labels for PRs belonging to a foreign repository.
- `OpenedHandler` can provision a brand-new `ReviewStack` (which is later deployed) attributed to a foreign repository, using attacker-supplied `pull_request.head.ref`/environment values.

This crosses the credential/repository trust boundary this Shipit instance is meant to enforce between tenants sharing one deployment.

### Likelihood Explanation
Requires a Shipit deployment configured with multiple GitHub organizations (`config/secrets.yml` `github:` keyed by org names) sharing one Shipit instance — a supported, documented configuration (`config/secrets.development.example.yml`). Any org onboarded onto that shared instance automatically gains the ability to forge cross-org webhook events, without needing GitHub App installation on the victim org, without needing the victim's `webhook_secret`, and without any Shipit session/API token — only the ability to send an arbitrary HTTP POST to the shared `/webhooks` endpoint with their own valid HMAC signature.

### Recommendation
After verifying the signature, cross-check that the organization/owner used for signature verification (`repository.owner.login` / `organization.login`) matches the owner encoded in `repository.full_name` (and any other repository identifiers the handlers rely on) before dispatching to handlers; reject the webhook (422) on mismatch. Alternatively, have handlers resolve the target `Repository`/`Stack` scoped to the verified `repository_owner` rather than trusting `full_name` independently.

### Proof of Concept
1. Configure Shipit for two organizations, `org-a` and `org-b`, each with its own `github.webhook_secret` in `config/secrets.yml`.
2. As an attacker who administers `org-a` (and thus knows `org-a`'s `webhook_secret` from their own GitHub App settings), craft a `pull_request` `closed` webhook payload:
```json
{
  "action": "closed",
  "number": 42,
  "pull_request": { ... },
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" },
  "sender": { "login": "attacker" }
}
```
3. Sign the raw body with `org-a`'s `webhook_secret` and set `X-Hub-Signature` accordingly; set `X-Github-Event: pull_request`.
4. POST to `/webhooks`. `verify_signature` computes `repository_owner` as `"org-a"`, fetches `org-a`'s `GitHubApp`, and the signature validates successfully.
5. `ClosedHandler#repository` resolves `Repository.from_github_repo_name("org-b/victim-repo")`, and `review_stack.archive!` is invoked on `org-b`'s real review stack — an unauthorized state change on a repository/organization the attacker has no legitimate relationship with.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
