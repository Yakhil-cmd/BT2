## Analog Found

### Title
Webhook signature validated against the payload's `repository.owner.login` while the event handler resolves and mutates the target repository/stack from `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config (and thus which `webhook_secret`) to validate the HMAC signature against by reading the *unverified* JSON body field `repository.owner.login` (with fallback to `organization.login`). [1](#0-0) [2](#0-1)  Once the signature check passes, every event handler independently resolves the target repository/stack from a *different* field of the same body, `repository.full_name`, via `Handler#repository_name`/`Repository.from_github_repo_name`. [3](#0-2) [4](#0-3)  Nothing ties the value used for signature-key selection (`repository.owner.login`) to the value used for target resolution (`repository.full_name`) - they are two independent, attacker-controlled strings inside the same unsigned-until-verified request body.

### Finding Description
Shipit supports multi-organization GitHub App configuration, where each organization has its own `webhook_secret`: [5](#0-4)  and the secrets example file documents this per-org schema. [6](#0-5) 

`verify_signature` performs:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` - fields taken straight from the untrusted, not-yet-verified raw body. [7](#0-6) 

`verify_webhook_signature` computes an HMAC of the *entire raw body* using the secret belonging to whichever organization name the attacker put in `repository.owner.login`: [8](#0-7) 

Crucially, the signature only proves "the sender knows OrgA's `webhook_secret`" - it does not constrain which repository the rest of the body claims to describe. After the signature check, `create` hands the parsed body to `Shipit::Webhooks.for_event(event)` handlers unchanged: [9](#0-8)  and every handler (`PushHandler`, `PullRequest::OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `LabeledHandler`, `UnlabeledHandler`, etc.) picks the target `Repository`/`Stack` using `payload.dig('repository', 'full_name')`: [3](#0-2) [10](#0-9) [11](#0-10) 

**The binding that is broken:** signature validity is scoped to `organization = repository.owner.login`, but the mutated resource is scoped to `repository = repository.full_name`. Nothing enforces `repository.full_name` starts with `repository.owner.login + "/"`. An attacker who is an authorized integrator/App installer for **any** configured organization (OrgA) knows or can obtain OrgA's genuine `webhook_secret` for that org's own installation. They can then POST directly to `/webhooks` (not through GitHub) with a body where `repository.owner.login = "OrgA"` (so the correct per-org secret is selected and HMAC validates) but `repository.full_name = "OrgB/target-repo"` (so the handler resolves and mutates a completely different organization's `Stack`/`Repository`, one the attacker has no legitimate relationship with).

This exactly mirrors the report's bug class: a hardcoded/derived trust anchor (`PREDICATE_ADDRESS`, here "the org whose secret verified the request") is used to authorize an action, while the actual object acted upon (the token to transfer/deposit, here "the repository resolved from `full_name`") is determined independently and can diverge from what was verified.

### Impact Explanation
This crosses the "cross-repository writes" bucket. With a validly-signed-for-OrgA payload but `full_name` pointed at OrgB's repo, an attacker can:
- Force `PushHandler` to call `stack.sync_github(expected_head_sha: ...)` on an OrgB `Stack` [12](#0-11) , which enqueues `GithubSyncJob` to fetch/attach GitHub commits and mutate `Stack` commit history/cache state for a repository the attacker doesn't own. [13](#0-12) 
- Force `PullRequest::OpenedHandler`/`ClosedHandler`/`ReopenedHandler`/`Labeled`/`UnlabeledHandler` to create, archive, or unarchive `ReviewStack`s belonging to OrgB's repositories. [14](#0-13) [15](#0-14) 

This is an unauthorized, unauthenticated-with-respect-to-the-target-org mutation of another organization's Shipit-managed state - state manipulation/writes across the organizational trust boundary that the webhook signature is supposed to establish.

### Likelihood Explanation
Requires the Shipit deployment to be configured with multiple GitHub organizations (an explicitly documented and supported configuration) and requires the attacker to know/possess the `webhook_secret` for at least one configured org (e.g., as a legitimate GitHub App installer/admin of their own org that is also onboarded to the same Shipit instance) while targeting a different org hosted on the same instance. This is plausible in any shared, multi-tenant Shipit deployment (the exact scenario `Shipit.github_app_config`/`github_organizations` is built for). No GitHub-side spoofing is required since the attacker posts directly to the `/webhooks` endpoint with their own valid HMAC.

### Recommendation
After signature verification, re-derive `repository_owner` from the same field the handlers use (`repository.full_name`'s owner segment) and require it to match the organization whose secret validated the signature; reject the webhook otherwise. Alternatively, have `verify_signature` and all `Handler#repository_name` resolution use one single, consistently-derived organization/repository identity, and assert equality between the two before invoking any handler.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (per the documented multi-org schema). [6](#0-5) 
2. As an attacker who knows/controls `OrgA`'s `webhook_secret` (e.g., they administer the GitHub App installation for their own `OrgA`), craft a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker_chosen_sha>",
  "repository": {
    "full_name": "OrgB/target-repo",
    "owner": { "login": "OrgA" }
  }
}
```
3. Compute `X-Hub-Signature: sha1=HMAC_SHA1(OrgA_webhook_secret, raw_body)`.
4. POST directly to `/webhooks` with `X-Github-Event: push` and the above signature.
5. `verify_signature` resolves `repository_owner` = `"OrgA"`, fetches OrgA's `GitHubApp`, and validates the HMAC successfully. [1](#0-0) 
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("OrgB/target-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker_chosen_sha>")` on OrgB's stack. [12](#0-11) [3](#0-2)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
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

**File:** app/jobs/shipit/github_sync_job.rb (L18-49)
```ruby
    def perform(params)
      @stack = Stack.find(params[:stack_id])
      expected_head_sha = params[:expected_head_sha]
      retry_count = params[:retry_count] || 0
      head_before_sync = spec_cache_target
      appended_commits = []

      handle_github_errors do
        new_commits, shared_parent = fetch_missing_commits { stack.github_commits }

        # Retry on Github eventual consistency: webhook indicated new commits but we found none
        if expected_head_sha && new_commits.empty? && !commit_exists?(expected_head_sha) &&
           retry_count < MAX_RETRY_ATTEMPTS
          GithubSyncJob.set(wait: RETRY_DELAY * retry_count).perform_later(params.merge(retry_count: retry_count + 1))
          return
        end

        stack.transaction do
          shared_parent&.detach_children!
          appended_commits = new_commits.map do |gh_commit|
            append_commit(gh_commit)
          end
          stack.lock_reverted_commits! if appended_commits.any?(&:revert?)
        end
      end
      sync_changed_nothing = appended_commits.empty? &&
                             spec_cache_target == head_before_sync &&
                             stack.cached_deploy_spec.present?
      return if sync_changed_nothing && !params[:force_spec_cache]

      CacheDeploySpecJob.perform_later(stack)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end
```
