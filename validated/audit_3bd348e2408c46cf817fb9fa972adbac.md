## Confirmed multi-org config
`Shipit` supports per-organization GitHub App configuration, each with its own `webhook_secret`, selected by `Shipit.github_app_config(organization)` [1](#0-0) , and instantiated per-org in `Shipit.github` [2](#0-1) .

### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but the repository actually written is looked up from the unrelated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which org's `webhook_secret` to use for HMAC verification based on `params.dig('repository','owner','login')` (or `organization.login`) [3](#0-2) [4](#0-3) . Once the signature check passes, every event `Handler` instead resolves the target `Repository`/`Stack` from a *different* field of the same payload, `repository.full_name`, via `Repository.from_github_repo_name` [5](#0-4) . `Repository.from_github_repo_name` performs a plain `find_by(owner:, name:)` lookup with **no scoping to the organization that was actually authenticated** [6](#0-5) .

### Finding Description
This mirrors the Flayer bug class: two related quantities (`listingCount` used for the checkpoint vs. the value actually mutated) are supposed to move together, but the code uses one for a security-relevant computation and a different one for the actual effect. Here the binding that should hold is:

`org whose webhook_secret verified the request == org owning the repository the handler writes to`

Both `repository.owner.login` and `repository.full_name` are attacker-supplied fields inside the same signed JSON body — the HMAC signature only proves that *some* value in the body was signed by a particular org's secret, not that these two specific sub-fields are internally consistent. In a Shipit deployment configured with `Shipit.github_apps` for multiple organizations (as exercised by `test/unit/github_apps_test.rb`, `OrgOne`/`OrgTwo` each with distinct `webhook_secret`s) [7](#0-6) , an org admin who legitimately owns their own GitHub App installation (and therefore legitimately knows their own `webhook_secret` — they created it in their own org's App settings, this is not a Shipit-privileged secret) can:

1. Set `repository.owner.login` (or `organization.login`) = their own org, so `verify_signature` picks their own org's `GitHubApp` and its `webhook_secret` [3](#0-2) .
2. Compute a valid `X-Hub-Signature` HMAC over the whole body using that secret they legitimately possess.
3. Set `repository.full_name` = `<victim-org>/<victim-repo>` — an arbitrary repository they don't own, tracked by Shipit for a different org/installation.

`verify_webhook_signature` will succeed (the HMAC matches the secret for the attacker's own org) [8](#0-7) , and the dispatched handler (e.g. `PushHandler`, `LabeledHandler`, `ReopenedHandler`, `ClosedHandler`, etc.) resolves `stacks`/`repository` purely from `repository.full_name`, unrelated to the org that was cryptographically verified [9](#0-8) [10](#0-9) .

### Impact Explanation
This breaks the "organization authenticated versus the repository that is written" binding explicitly listed in scope. Concretely, an attacker who controls a legitimate org's GitHub App/webhook secret can forge webhook events that:
- Force `Stack#sync_github` on a victim's repository/branch via `PushHandler` (cross-repository write / state manipulation) [11](#0-10) .
- Archive/unarchive victim `ReviewStack`s via `LabeledHandler`/`ReopenedHandler`/`ClosedHandler`, which call `stack.deprovision`/`stack.archive!`/`stack.unarchive!` — actions that can trigger deploy/deprovision task execution for repositories the attacker has no authorization over [12](#0-11) .

This is a cross-repository write achieved without any Shipit session, API token, or the victim org's own webhook secret — satisfying the Critical "cross-repository writes" bar.

### Likelihood Explanation
Requires a multi-org Shipit deployment (`Shipit.github_apps`) where the attacker legitimately administers at least one configured GitHub App/org (and thus its `webhook_secret`, which is not a Shipit secret but one the org's own admin necessarily possesses) while other orgs' repositories are also tracked by the same Shipit instance. This is a realistic and documented supported configuration (see the double-github-app fixtures/tests), making the likelihood moderate-to-high for any Shipit installation onboarding multiple independent GitHub organizations.

### Recommendation
After `verify_signature` succeeds, re-derive `repository_owner` and enforce that it matches the owner segment of `repository.full_name` (or `organization.login`) before dispatching to handlers; alternatively, have `Handler#stacks`/`#repository` scope `Repository.from_github_repo_name` lookups by the same verified organization used in `WebhooksController#verify_signature`, rejecting (422) any payload where these disagree.

### Proof of Concept
1. Configure Shipit with two orgs, `orgA` (attacker-controlled GitHub App, secret known to attacker) and `orgB` (victim, tracked repository `orgB/victim-repo`).
2. Attacker crafts a `push` webhook JSON body: `{"ref": "refs/heads/main", "after": "<sha>", "repository": {"owner": {"login": "orga"}, "full_name": "orgb/victim-repo"}}`.
3. Attacker computes `X-Hub-Signature: sha1=<hmac-sha1(orgA_webhook_secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` looks up `Shipit.github(organization: 'orga')`, verifies the signature successfully against `orgA`'s secret [3](#0-2) .
5. `PushHandler#process` calls `stacks` → `Handler#stacks` → `Repository.from_github_repo_name('orgb/victim-repo')` → resolves `orgB`'s stack and calls `stack.sync_github(...)` on it, despite the request never being signed by `orgB`'s secret [5](#0-4) [11](#0-10) .

### Citations

**File:** lib/shipit.rb (L170-181)
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
```

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** test/unit/github_apps_test.rb (L1-20)
```ruby
# frozen_string_literal: true

require 'test_helper'

module Shipit
  class GitHubAppsTestOrgOne < ActiveSupport::TestCase
    setup do
      @organization = "OrgOne"
      @github = app(@organization)
      @enterprise = app(@organization, domain: 'github.example.com')
      @rails_env = Rails.env
      @token_cache_key = "github:integration:#{@organization.downcase}:access-token"
      Rails.cache.delete(@token_cache_key)
    end

    teardown do
      Rails.env = @rails_env
      Rails.cache.delete(@token_cache_key)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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
    end
  end
end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-68)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L23-50)
```ruby
          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end

          def unarchive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no ReviewStack exists. Creating."
              )
              return create!
            end
            return unless stack.archived?

            stack.transaction do
              Shipit::ReviewStackProvisioningQueue.add(stack)
              stack.unarchive!(*args, &block)
            end
          end
```
