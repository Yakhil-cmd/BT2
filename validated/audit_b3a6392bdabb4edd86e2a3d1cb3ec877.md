## Title
Webhook signature verification is keyed to `repository.owner.login` while every event handler acts on the unvalidated `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit's `WebhooksController` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken directly from the untrusted JSON body, but every downstream `Webhooks::Handlers::Handler` subclass resolves the target `Repository`/`Stack` using a *different* field from that same body — `repository.full_name`. Because nothing enforces that `full_name` is actually prefixed by `owner.login`, an operator of any GitHub organization that is configured in Shipit's multi-org `secrets.github` block can sign a payload with their own legitimate webhook secret while setting `full_name` to point at a completely different, victim organization's repository already registered in Shipit.

### Finding Description
`WebhooksController#verify_signature` looks up the app config to verify against like this: [1](#0-0) 

with `repository_owner` defined as: [2](#0-1) 

The HMAC (`verify_webhook_signature`) is computed over the entire `request.raw_post`, so it does authenticate that the *whole* payload came from whichever organization's secret was selected — but the secret selection itself is driven by attacker-controlled JSON (`repository.owner.login`), and the **business logic never re-checks that same field**. Every `Handler` subclass instead resolves the acted-upon repository purely from `repository.full_name`: [3](#0-2) 

This is used identically in `PushHandler` (`stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(...) }`) and in every `PullRequest::*Handler` (`OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `Labeled/UnlabeledHandler`, `LabelCapturingHandler`), all of which call `Shipit::Repository.from_github_repo_name(params.repository.full_name)`: [4](#0-3) [5](#0-4) 

Because Shipit explicitly supports (and documents) hosting multiple independent GitHub organizations under one instance, each with its own `webhook_secret` in `secrets.github`: [6](#0-5) [7](#0-6) 

the equality the app relies on but never checks is:

`organization whose secret authenticated the request (repository.owner.login)` == `repository whose Stack/Repository record is mutated (repository.full_name)`

Before the attacker's forged request: repository_owner = "attacker-org", full_name = "attacker-org/some-repo" (legitimate, matches). After: an attacker who controls "attacker-org" (a real, Shipit-configured tenant) crafts and correctly HMAC-signs (with their own valid webhook secret) a payload where `repository.owner.login = "attacker-org"` but `repository.full_name = "victim-org/victim-repo"`. `verify_signature` picks `Shipit.github(organization: "attacker-org")`, successfully verifies the signature (since it's genuinely signed by that org's secret), and the handler then acts on the "victim-org/victim-repo" `Stack`, which the attacker has no legitimate access to.

### Impact Explanation
For `push` events this lets the attacker enqueue `GithubSyncJob`/`sync_github` for any registered stack the attacker chooses, regardless of tenant boundary — and if that stack has `continuous_deployment: true`, a spoofed `after` SHA / spec-cache resync can trigger `ContinuousDeliveryJob` and an actual deploy of the victim's stack: [8](#0-7) [9](#0-8) 

For `pull_request` events, the attacker can create/archive/unarchive Review Stacks belonging to a victim repository (`ReviewStackAdapter#find_or_create!` / `#archive!` / `#unarchive!`), which provisions and can trigger deploy steps for infrastructure the attacker does not own. This crosses the "cross-repository writes / unauthorized deploy" threshold defined as Critical impact, since the tenant boundary between GitHub organizations sharing one Shipit instance is broken entirely by webhook forgery rather than any credential compromise.

### Likelihood Explanation
Exploitation requires only that the attacker control (or be an admin of) any single GitHub organization/App that a Shipit operator has legitimately configured as one of several tenants in `secrets.github` (a documented, supported multi-org configuration) — no compromise of the victim org, its webhook secret, or Shipit credentials is needed. The attacker only needs to craft an arbitrary JSON body and sign it with their own legitimate, self-controlled webhook secret, which is fully within their control by design.

### Recommendation
In `Webhooks::Handlers::Handler#stacks`/`#repository_name` (and in every handler that resolves a `Repository`/`Stack` from `params.repository.full_name`), verify that the resolved repository's `owner` matches the `repository_owner`/organization that was cryptographically authenticated in `WebhooksController#verify_signature`. Concretely, pass the verified organization down to `Webhooks.for_event(event).each { |handler| handler.call(params) }` and have `Handler#stacks` reject (or the controller reject before dispatch) any payload where `Repository.from_github_repo_name(repository_name)&.owner` does not case-insensitively equal `repository_owner`.

### Proof of Concept
Given a Shipit instance configured with two tenants, `attacker-org` (attacker-controlled, webhook secret known to attacker) and `victim-org` (unrelated, existing Stack `victim-org/victim-repo`):

```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org's webhook_secret, body)>

{
  "ref": "refs/heads/main",
  "after": "<any sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```

`verify_signature` computes `repository_owner = "attacker-org"`, loads `Shipit.github(organization: "attacker-org")`, and the signature validates because the attacker legitimately controls that secret. `PushHandler#process` then resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` — a stack the attacker has never had access to — and calls `stack.sync_github(expected_head_sha: ...)`, which for a continuously-deployed victim stack can trigger an unauthorized deploy.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

**File:** app/jobs/shipit/continuous_delivery_job.rb (L1-22)
```ruby
# frozen_string_literal: true

module Shipit
  class ContinuousDeliveryJob < BackgroundJob
    include BackgroundJob::Unique

    queue_as :deploys
    on_duplicate :drop

    def perform(stack)
      return unless stack.continuous_deployment?

      # If there is a schedule defined for this stack, make sure we are within a
      # deployment window before proceeding.
      return if stack.continuous_delivery_schedule && !stack.continuous_delivery_schedule.can_deploy?

      # checks if there are any tasks running, including concurrent tasks
      return if stack.occupied?

      stack.trigger_continuous_delivery
    end
  end
```

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```
