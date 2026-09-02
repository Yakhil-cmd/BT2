### Title
Webhook signature is verified against the organization in `repository.owner.login`, but the repository actually mutated is taken from the unverified `repository.full_name` field, allowing cross-organization forgery in a multi-tenant Shipit install - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-org Shipit deployment (`Shipit.github(organization:)` selects a per-organization GitHub App/config, as shown by `test/dummy/config/secrets_double_github_app.yml` defining `OrgOne`/`OrgTwo`), `WebhooksController#verify_signature` picks the HMAC secret to verify with based on one payload field (`repository.owner.login`, falling back to `organization.login`), while every event `Handler` (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, the `PullRequest::*Handler`s, etc.) resolves the actual repository/stack to act on from a *different* payload field, `repository.full_name`. These two fields are never cross-checked against each other.

### Finding Description
`WebhooksController#verify_signature` computes the signing organization purely from attacker-controlled JSON body content: [1](#0-0) [2](#0-1) 

`repository_owner` reads `params.dig('repository', 'owner', 'login')` (or `organization.login`) and is used to select `Shipit.github(organization: repository_owner)`, i.e., which GitHub App config/`webhook_secret` is used to verify `X-Hub-Signature`: [3](#0-2) 

Once the signature check passes, `WebhooksController#create` dispatches the entire raw payload to the registered handler(s) unchanged: [4](#0-3) 

But the base `Handler` class - and therefore every concrete handler that inherits `stacks`/`repository_name` - resolves the repository to operate on from `repository.full_name`, a field that is completely independent of `repository.owner.login`: [5](#0-4) 

Concrete handlers such as `PushHandler` (`stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(...) }`), `StatusHandler` (`Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`), and the `PullRequest::*Handler`s all key off `params.repository.full_name`, never re-deriving or asserting that it matches the organization whose secret validated the request: [6](#0-5) [7](#0-6) [8](#0-7) 

Repository lookup itself has no ownership constraint tying it back to the signing organization - it is a flat `owner/name` lookup: [9](#0-8) 

**The broken binding, stated as an equality that should hold but doesn't:**
`organization used to select webhook_secret for HMAC verification (repository.owner.login)` == `organization of the repository whose Stack/Commit/PullRequest state is mutated (repository.full_name)`.

Before an attacker's request: for legitimate GitHub-originated webhooks these two fields always describe the same repository, so the equality holds implicitly (GitHub sets both fields from the same underlying repo object). Nothing in the code enforces the equality explicitly, though.

After the attacker's request: an attacker who controls (or has been granted, as an org admin) a GitHub App installation for **their own** organization, `OrgAttacker`, on a Shipit instance configured with multiple GitHub orgs (as the multi-org secrets format explicitly supports), knows `OrgAttacker`'s `webhook_secret`. They can send a POST to `/webhooks` with:
- `X-Hub-Signature` computed with `OrgAttacker`'s known secret,
- `repository.owner.login = "OrgAttacker"` (so `verify_signature` picks `OrgAttacker`'s config and the signature verifies),
- `repository.full_name = "OrgVictim/some-repo"` (a repository that is actually configured as a Stack on the same Shipit instance under a different, victim organization).

The handler will act on `OrgVictim/some-repo` because it only reads `repository.full_name`. The two fields are never required to be consistent, so the org whose secret authenticated the request is not the org/repository actually mutated.

### Impact Explanation
This breaks the deployment-trust binding between "organization that authenticated the webhook" and "repository that is written," which is explicitly one of the listed in-scope binding classes. Concretely, in a multi-org Shipit instance:
- `StatusHandler#process` lets the attacker inject a forged commit status (`create_status_from_github!`) onto a victim-org commit. Since `ci.require` gates deploys on commit statuses (per README `ci.require`), this can be used to falsely satisfy CI requirements and enable an **unauthorized deploy** of a victim's stack by cooperating with a subsequent legitimate/forced deploy trigger, or at minimum corrupt the victim's CI/status state that deploy decisions depend on.
- `PushHandler#process` can trigger `stack.sync_github` for a victim stack using an attacker-chosen `expected_head_sha`, causing the victim stack to sync against attacker-influenced state.
- `PullRequest::*Handler`s can archive/unarchive victim review stacks or overwrite victim `PullRequest` records' `github_pull_request` cache.

The most severe of these (status forgery feeding CI-gated deploys) rises to "unauthorized deploy," matching the High-impact bucket in scope. This requires no `ApiClient` token, no `webhook_secret` of the victim org, no repository write access to the victim repo, and no privileged Shipit account - only an attacker-controlled GitHub App/org that the instance operator has configured as one tenant among several.

### Likelihood Explanation
This requires the deployment to be configured in the multi-organization GitHub App mode (keyed secrets like the `OrgOne`/`OrgTwo` example in `test/dummy/config/secrets_double_github_app.yml`), where the attacker legitimately controls one tenant org's GitHub App/webhook secret but Shipit also hosts stacks belonging to other organizations. This is a supported, documented configuration shape, not a hypothetical misuse, but it does depend on that multi-tenant setup existing; a single-org Shipit instance is not exposed to this specific cross-org path (though the underlying lack of cross-checking is still present in the code).

### Recommendation
In `Handler#stacks`/`#repository_name` (and anywhere handlers key off `repository.full_name`), verify that the repository's owner matches the organization that was used to validate the webhook signature (i.e., thread `repository_owner`/verified organization from `WebhooksController` into the handler and assert `repository.full_name.split('/').first.casecmp(verified_organization) == 0`), rejecting/dropping events where they disagree. Alternatively, always verify using the organization inferred from `repository.full_name` itself rather than from `repository.owner.login`/`organization.login`, so a single field drives both signature verification and the mutation target.

### Proof of Concept
1. Configure Shipit with multi-org GitHub Apps, e.g. `OrgAttacker` and `OrgVictim`, each with distinct `webhook_secret`s (as in `test/dummy/config/secrets_double_github_app.yml`).
2. Attacker knows `OrgAttacker`'s `webhook_secret` (they administer that GitHub App/org).
3. Attacker crafts a `status` webhook payload:
   ```json
   {
     "sha": "<victim commit sha>",
     "state": "success",
     "context": "ci/required-check",
     "repository": { "owner": { "login": "OrgAttacker" }, "full_name": "OrgVictim/victim-repo" }
   }
   ```
4. Attacker computes `X-Hub-Signature` using `OrgAttacker`'s `webhook_secret` over this exact body and sends it to `POST /webhooks` with `X-Github-Event: status`.
5. `WebhooksController#verify_signature` reads `repository_owner == "OrgAttacker"`, loads `OrgAttacker`'s app/secret via `Shipit.github(organization: "OrgAttacker")`, and the signature verifies successfully.
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and calls `create_status_from_github!(params)` for the victim commit belonging to `OrgVictim`, injecting a forged `success` status that can satisfy `ci.require` for a deploy of `OrgVictim`'s stack - despite the attacker never having credentials for `OrgVictim`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-53)
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
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
