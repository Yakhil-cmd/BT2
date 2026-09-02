### Title
Cross-organization webhook authentication bypass allows forged push/status events to trigger unauthorized syncs and deploys on repositories the attacker does not control - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/HMAC secret to verify a webhook against using `repository_owner`, a field read directly out of the unverified request body [1](#0-0) . Once verification passes, `create` dispatches the same body to a `Handler`, which decides *which repository/stack to act on* using an entirely different field, `repository.full_name` [2](#0-1) . The organization whose credential authenticated the request is never bound to the repository that is actually written to, breaking the equality `authenticated_org == written_repo.owner`.

### Finding Description
The webhook signature check is:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 

`repository_owner` is read from the same untrusted JSON body that is being verified, and it is used only to look up *which secret* to check the HMAC against, via `Shipit.github(organization:)` → `github_app_config(organization)` [4](#0-3) . In a multi-org Shipit deployment, each organization owns its own `webhook_secret` (`config/secrets.development.shopify.yml` shows the multi-org schema, and `webhook_secret` is explicitly documented/allowed to be blank) [5](#0-4) . `GitHubApp#verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [6](#0-5) 

After the signature check passes, `create` re-parses the same raw body and dispatches it to event handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  ...
end
``` [7](#0-6) 

Every handler resolves the target repository/stack from `repository.full_name`, not from `repository.owner.login`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [8](#0-7) 

`PushHandler#process` then acts on whatever stack matches that `full_name`:
```ruby
def process
  stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [9](#0-8) 

Because `repository.owner.login` (used to pick the HMAC secret) and `repository.full_name` (used to pick the acted-upon repository) are independent fields inside the same JSON body, and only the *organization the secret belongs to* is authenticated — never the *repository the payload claims to describe* — an attacker who controls (or is allowed to onboard) any organization configured in this Shipit instance can forge a webhook whose `repository.owner.login` matches their own org (so the signature check passes against their own/known secret, or trivially passes if that org's `webhook_secret` is unset) while `repository.full_name` names a stack belonging to a completely different, victim organization.

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" trust binding explicitly called out as in-scope. The unprivileged-relative-to-the-victim-org attacker can:
- Enqueue `GithubSyncJob` for a victim stack with an attacker-chosen `expected_head_sha` [10](#0-9) , forcing Shipit to poll/re-sync a victim repository on demand.
- On stacks with `continuous_deployment` enabled, forging a push causes `GithubSyncJob` to append newly-fetched real commits and invoke `CacheDeploySpecJob` [11](#0-10) , feeding the continuous-delivery pipeline (`Stack.schedule_continuous_delivery` / `ContinuousDeliveryJob`) that ultimately triggers deploys — i.e. an attacker can force an out-of-band, attacker-timed deploy trigger on a repository they do not own.
- Other handlers keyed the same way (status, check_suite, pull_request label handlers, membership) allow cross-org spoofing of commit statuses, check-run refreshes, and review-stack archive/unarchive actions [12](#0-11) .

This matches the accepted "unauthorized deploy" / cross-repository write impact class.

### Likelihood Explanation
Likelihood depends on the deployment supporting multiple GitHub organizations (the documented multi-org `secrets.yml` schema) where at least one configured org either has a blank `webhook_secret` (explicitly supported per `docs/setup.md`/example secrets files) or one whose secret the attacker otherwise possesses legitimately for their own org. In such setups, no privileged Shipit session, API token, or victim secret is required — only the ability to send an HTTP POST to `/webhooks` with a crafted body and a signature valid for the attacker's own (or secret-less) organization. Single-org deployments are not affected by this specific bypass, since `repository_owner` will then only ever resolve to the one configured org's secret; this reduces exploitability breadth but the vulnerable binding itself (owner-for-auth vs. full_name-for-write) exists in the code regardless.

### Recommendation
After signature verification, re-validate that `repository.full_name`'s owner segment matches the `repository_owner` (or `organization.login`) that was actually used to select and verify the HMAC secret, and reject the webhook if they differ. Alternatively, derive `repository_owner` strictly from `repository.full_name`'s owner segment (a single source of truth) rather than from a separate, independently-authenticated field, so the same value is used both to pick the verification secret and to resolve the acted-upon repository.

### Proof of Concept
1. Deploy Shipit with the multi-org config schema (`config/secrets.*.yml` with two orgs, e.g. `attacker-org` and `victim-org`), where `attacker-org` has `webhook_secret: nil` (a documented, supported configuration) or a secret known to the attacker.
2. Attacker POSTs to `/webhooks` with:
   - Header `X-Github-Event: push`
   - Header `X-Hub-Signature`: absent/arbitrary (auto-verified `true` for `attacker-org` per `GitHubApp#verify_webhook_signature`) or correctly computed with the attacker's own known secret.
   - Body:
     ```json
     {
       "ref": "refs/heads/main",
       "after": "<victim commit sha>",
       "repository": {
         "full_name": "victim-org/victim-repo",
         "owner": { "login": "attacker-org" }
       }
     }
     ```
3. `verify_signature` computes `repository_owner == "attacker-org"`, looks up `attacker-org`'s config, and passes verification [1](#0-0) .
4. `create` dispatches the payload to `PushHandler`, which resolves the target via `repository.full_name == "victim-org/victim-repo"` [2](#0-1) , matches the real victim stack, and calls `stack.sync_github(expected_head_sha: "<victim commit sha>")` [9](#0-8) , queuing `GithubSyncJob` for a repository the attacker never proved ownership of.

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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L41-68)
```ruby
          def process
            return unless respond_to_label_change?

            handle
          end

          private

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
