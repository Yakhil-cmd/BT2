### Title
Webhook signature verification is bound to `repository.owner.login` but push processing is bound to the unrelated `repository.full_name` field, allowing cross-organization webhook forgery in multi-tenant GitHub App configurations - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` authenticates an inbound webhook using `repository_owner` (`repository.owner.login`, or `organization.login`) taken from the still-untrusted JSON body [1](#0-0) . Once the HMAC check passes for that organization's secret, `Shipit::Webhooks::Handlers::Handler#repository_name`/`#stacks`, used by `PushHandler`, resolve the actual `Stack` to act on from a **different** field, `repository.full_name` [2](#0-1) . Nothing in the code cross-checks that the owner segment of `full_name` matches `repository.owner.login`. In a multi-organization deployment (the documented schema where `secrets.github` has one sub-key per organization, each with its own `webhook_secret`) this breaks the binding: `verified organization == acted-upon repository`.

### Finding Description
`Shipit.github(organization:)` looks up the app config keyed by the caller-supplied `organization` argument and raises only if that organization is entirely unknown [3](#0-2) . In multi-org mode (`github_default_organization` non-nil), the `organization:` argument genuinely selects which app/secret is used to validate `X-Hub-Signature` [4](#0-3) , as documented by the multi-organization secrets schema [5](#0-4) .

`WebhooksController#verify_signature` derives that organization from `repository.owner.login` in the JSON payload itself: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [6](#0-5) . Signature verification with HMAC-SHA1 (`verify_webhook_signature`) does authenticate that the whole raw body was signed by whatever secret belongs to that organization [7](#0-6) .

The problem: the *content* of the body is not otherwise constrained to be self-consistent. `PushHandler#process` never consults `repository.owner.login`; it resolves the target repository purely from `repository.full_name` via `Handler#repository_name`/`#stacks` [8](#0-7) [2](#0-1) . A legitimate GitHub-generated payload always has `repository.owner.login` matching the owner prefix of `repository.full_name`, but nothing in Shipit enforces this equality — the two fields are read independently by two different pieces of code that trust different signing keys.

Any actor who legitimately controls a GitHub App installation on **their own** organization configured in Shipit's multi-org `secrets.github` map (and therefore can produce a validly-signed webhook body using their own org's `webhook_secret`) can set `repository.owner.login = <their-own-org>` (so the signature check passes) while setting `repository.full_name = "<victim-org>/<victim-repo>"` (so `PushHandler` acts on a stack belonging to a repository they have no relationship to). This crosses exactly the trust boundary "an organization that authenticated versus the repository that is written."

### Impact Explanation
Successful forgery lets an attacker who only controls one tenant/organization in a multi-org Shipit deployment enqueue `GithubSyncJob` for any stack backed by a different organization's repository [9](#0-8) . `GithubSyncJob` uses Shipit's own stored GitHub credentials for that stack's repository to pull commits and append them to the stack, then triggers `CacheDeploySpecJob` [10](#0-9) . On stacks with continuous delivery/auto-deploy enabled, this synchronization step is what drives automatic deployment of newly observed commits — meaning the attacker can force the victim's repository sync/deploy pipeline to progress at a time of their choosing (an unauthorized deploy trigger against a repository the attacker does not own), purely by holding credentials for their own, unrelated tenant.

### Likelihood Explanation
This requires the deployment to use Shipit's multi-organization GitHub App configuration schema (each org with a distinct `webhook_secret`), which is an explicitly documented, supported configuration for SaaS-style multi-tenant use of the engine [5](#0-4) . Any tenant able to install their own GitHub App/receive their own valid webhook signature (an "unprivileged attacker" relative to other tenants' repositories) can exploit this without needing any secret, session, or credential belonging to the victim organization.

### Recommendation
In `WebhooksController`/`Handler`, after signature verification succeeds for organization `O`, require that the repository object being acted on (`repository.full_name`'s owner segment, or `organization.login`) equals `O`, rejecting (422) any payload where they diverge. Alternatively, resolve the target `Stack`/`Repository` scoped to organization `O` rather than trusting `repository.full_name` globally.

### Proof of Concept
1. Deploy Shipit with multi-org config: organizations `attacker-org` and `victim-org`, each with a distinct configured `webhook_secret`.
2. Attacker controls a GitHub App/webhook sender for `attacker-org` and thus can compute a valid HMAC using `attacker-org`'s `webhook_secret`.
3. Attacker crafts a JSON push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
4. Attacker signs the raw body with `attacker-org`'s `webhook_secret` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` computes `repository_owner` = `"attacker-org"`, loads `attacker-org`'s app, and the signature verifies successfully [11](#0-10) .
6. `PushHandler#process` resolves stacks via `repository.full_name` = `"victim-org/victim-repo"` and enqueues a sync/deploy cycle for the victim's stack [9](#0-8) , even though the attacker has no relationship with `victim-org`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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
