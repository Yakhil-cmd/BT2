### Title
Cross-repository forgery of commit CI status via unscoped `StatusHandler` enables unauthorized continuous-delivery deploys - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates an incoming GitHub `status` webhook against the `GitHubApp` (and its `webhook_secret`) resolved from the *organization* named in the payload, but `Shipit::Webhooks::Handlers::StatusHandler#process` writes the resulting `Status` record by looking up commits **globally by `sha`**, with no check that the commit's stack/repository belongs to that same organization. This breaks the binding "organization that authenticated == repository that is written."

### Finding Description
The webhook signature check resolves which GitHub App/secret to verify against purely from the payload's own `repository.owner.login` (or `organization.login`) field: [1](#0-0) 

That secret is looked up per-organization via `Shipit.github(organization:)`: [2](#0-1) 

Once the HMAC is valid for *that* organization, the controller dispatches the entire raw payload to all registered handlers for the event, unconditionally: [3](#0-2) 

Most handlers scope their effect to the repository named in the payload via `Handler#stacks`/`Repository.from_github_repo_name`: [4](#0-3) 

`StatusHandler`, however, does not use that scoping at all — it resolves the target purely by commit SHA across the entire database: [5](#0-4) 

Creating a `Status` triggers automatic continuous-delivery scheduling regardless of which organization "authenticated" the request: [6](#0-5) 

`Commit#deployable?` treats a `success` status (matching the stack's required CI contexts) as sufficient to allow deploy, and a status transition to success/pending schedules merges and continuous delivery: [7](#0-6) [8](#0-7) 

Concretely, in a Shipit instance configured with multiple GitHub Apps for multiple organizations (a supported, documented configuration): [9](#0-8) 

an attacker who legitimately controls/administers one organization's GitHub App integration (and therefore possesses that org's `webhook_secret`, which they configured themselves) can craft an arbitrary JSON body for the `status` event — setting `sha` to a commit SHA belonging to a *different* organization's/stack's repository, with `state: success` and a `context` matching that victim stack's required CI check. `WebhooksController#verify_signature` only validates the HMAC against their own org's secret (which they legitimately possess), and never checks that the `sha`/`context` in the body actually belongs to that org's repositories. `StatusHandler#process` then writes a `Status` on the victim commit regardless of organization, potentially satisfying `Commit#deployable?` and firing `ContinuousDeliveryJob`/merge processing.

Additionally, since a webhook secret is documented as optional per organization (`webhook_secret: # nil`) and `verify_webhook_signature` auto-passes when no secret is configured: [10](#0-9) 

any organization onboarded without a configured secret allows a fully unauthenticated attacker (no credential at all) to forge the same `status` payload targeting any other organization's commits.

### Impact Explanation
This can result in an unauthorized deploy: a forged `success` status on a victim stack's commit can make that commit `deployable?`, and the `Status#after_commit` hook schedules `ContinuousDeliveryJob`/`ProcessMergeRequestsJob`, which can trigger an actual deploy of that commit in production if the stack has continuous deployment enabled. This matches the Critical bucket ("unauthorized deploy") and, at minimum, the High bucket via cross-tenant interference with stack/CI state that should be isolated per GitHub organization.

### Likelihood Explanation
Requires: (a) a multi-organization Shipit deployment (explicitly documented/supported), and (b) the attacker to possess a valid `webhook_secret` for any one configured organization (which they would legitimately hold if they administer that org's GitHub App) — or for any organization onboarded without a webhook secret, no credential at all is needed. Given webhook secrets are explicitly optional per the setup docs, and multi-org support is a documented feature, this is a realistic configuration, not a violation of documented deployment assumptions.

### Recommendation
`StatusHandler` (and any other handler bypassing `Handler#stacks`) must scope commit/status lookups to the repository named in the payload (`payload.dig('repository', 'full_name')`), and that repository's owning organization must be verified to match the organization whose secret authenticated the webhook (`repository_owner` used in `verify_signature`). Reject or ignore events where the authenticated organization does not match the repository's actual organization.

### Proof of Concept
1. Configure Shipit with two GitHub Apps, `OrgA` and `OrgB`, each with its own `webhook_secret` (multi-org config per `docs/setup.md`), and stacks tracking commits for both orgs.
2. As an attacker who administers `OrgA`'s GitHub App (and thus knows `OrgA`'s `webhook_secret`), obtain (e.g. via GitHub's public API) the commit SHA of an undeployed commit on `OrgB/victim-repo`'s tracked branch, and the CI context required by that stack's `shipit.yml` (`ci.require`).
3. POST to `/webhooks` with header `X-Github-Event: status`, body:
```json
{
  "sha": "<victim-org-commit-sha>",
  "state": "success",
  "context": "<required-ci-context>"
}
```
signed with `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, raw_body)>`.
4. `verify_signature` resolves `repository_owner` (absent a `repository` key, falls back to `organization.login`, which the attacker can omit/spoof or simply rely on there being no `repository` object) and verifies against `OrgA`'s secret — succeeds.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the `OrgB` commit, and creates a `success` `Status` on it, unaware of any organization mismatch, potentially triggering `ContinuousDeliveryJob` for `OrgB`'s stack.

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

**File:** app/models/shipit/status.rb (L18-44)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
    end

    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```

**File:** app/models/shipit/commit.rb (L219-229)
```ruby
    delegate :pending?, :success?, :error?, :failure?, :blocking?, :state, to: :status

    def active?
      return false unless stack.active_task?

      stack.active_task.includes_commit?(self)
    end

    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L366-385)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
