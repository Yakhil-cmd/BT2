This confirms the vulnerability. `Shipit.github(organization:)` selects a webhook secret keyed only by the organization name string passed in, with multi-org support explicitly documented via per-org `webhook_secret` config, as shown in `config/secrets.development.shopify.yml`.### Title
Webhook signature verification is keyed by an attacker-influenced payload field that is decoupled from the repository the event handler actually acts on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate an incoming webhook against by reading `repository.owner.login` (or `organization.login`) directly out of the *unverified* JSON body, before the HMAC signature has been checked. [1](#0-0) [2](#0-1)  Once the signature check passes against *some* organization's secret, `Shipit::Webhooks::Handlers::Handler` (and every handler built on it, e.g. `PushHandler`, the `PullRequest::*` handlers) resolves the actual repository/stack to mutate from a *different* payload field, `repository.full_name`, with no cross-check that this repository belongs to the organization whose secret validated the request. [3](#0-2) 

### Finding Description
Shipit natively supports multiple GitHub organizations, each with its own independent `webhook_secret`, `app_id`, `installation_id`, etc., as documented in `config/secrets.development.shopify.yml`. [4](#0-3)  `Shipit.github(organization:)` looks up the app config purely by the `organization` string key supplied to it, with no relation to any other trust boundary. [5](#0-4) [6](#0-5) 

In `WebhooksController`, the `organization` used to select the secret for HMAC verification is derived straight from the incoming, not-yet-verified JSON body:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [7](#0-6) 

The equality this code implicitly assumes is: *"the organization whose secret verified this request" == "the organization that owns the repository the handler will mutate."* But that binding is never enforced. After signature verification passes (proving only that *the request was signed by organization X's secret*), the actual event handlers (`PushHandler`, all `PullRequest::*Handler`s, `StatusHandler`, etc.) independently re-read `repository.full_name` from the same untrusted body via `Handler#repository_name`/`Repository.from_github_repo_name` to decide which `Stack`/`Repository` record to act on — with no check that this repository's owner matches the `repository_owner` used during signature verification. [3](#0-2) [8](#0-7) [9](#0-8) 

Concretely: if a Shipit instance is configured with two organizations, `OrgA` and `OrgB` (each with its own GitHub App and `webhook_secret`, as the multi-org config format supports [4](#0-3) ), an attacker who legitimately controls `OrgA`'s webhook secret (e.g. is an admin of `OrgA`'s GitHub App/installation, a low-privilege position relative to `OrgB`) can craft an HTTP POST to `/webhooks` where:
- `repository.owner.login` = `"OrgA"` (so `verify_signature` selects `OrgA`'s secret, which the attacker holds, and the HMAC check passes), but
- `repository.full_name` = `"OrgB/some-repo"` (so the handler resolves and mutates `OrgB`'s repository/stack).

Because `Repository.from_github_repo_name` only splits `owner/name` from the payload and does a direct DB lookup with no ownership cross-check against the verified organization, this event will be accepted as a legitimately-signed webhook for `OrgB`'s repository. [9](#0-8) 

This maps to the external report's bug class ("single/unvalidated trust source drives state changes without cross-validation") as an analog: the binding "signed-by organization == acted-upon organization" is broken, exactly like the reported binding "trusted Ethereum data source == data actually consumed for chain state."

### Impact Explanation
Depending on which handler fires, this can drive unauthorized state changes on another organization's stack using only a secret the attacker legitimately controls for their own, unrelated organization:
- `push` event → `PushHandler` triggers `GithubSyncJob`, causing Shipit to sync commits and (via `stack.sync_github`) potentially advance deploy state for a repository the attacker does not own. [10](#0-9) [11](#0-10) 
- `pull_request` events → `ReviewStackAdapter`-backed handlers can archive/unarchive/create review stacks on a targeted repository. [12](#0-11) [13](#0-12) 

This effectively lets an attacker spoof events as though they originated from another organization's repository, injecting forged state transitions into stacks they don't control, which aligns with "cross-repository writes" / unauthorized deploy-adjacent state manipulation.

### Likelihood Explanation
Requires: (1) the target Shipit deployment to be configured with multiple organizations (a documented, supported configuration, not a misconfiguration), and (2) the attacker to control (or compromise) a legitimate webhook secret for any one of those organizations — a much lower bar than compromising `OrgB` directly. Given multi-tenant Shipit deployments servicing several GitHub orgs are an explicit, documented use case, this is realistic wherever that pattern is used.

### Recommendation
- After signature verification, re-derive the organization from the *handler's* resolved repository (`repository.full_name`'s owner) and require it to equal the `repository_owner`/`organization.login` used to select the verifying secret; reject the webhook if they differ.
- Alternatively, verify the payload's signature against the specific organization owning `repository.full_name`, not a value read from an unauthenticated field chosen independently by the attacker, and re-validate consistency between `repository.owner.login`/`organization.login` and `repository.full_name`'s owner before dispatching to handlers.
- Log and reject (422) any webhook where these two derived organizations disagree.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` (attacker-controlled GitHub App/secret) and `OrgB` (victim), per the documented multi-org `config/secrets.*.yml` format. [4](#0-3) 
2. Attacker computes `X-Hub-Signature` using `OrgA`'s known `webhook_secret` over a crafted `push` payload where:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen sha>",
     "repository": { "full_name": "OrgB/victim-repo", "owner": { "login": "OrgA" } }
   }
   ```
3. POST to `/webhooks` with `X-Github-Event: push` and the `OrgA`-signed `X-Hub-Signature`.
4. `verify_signature` computes `repository_owner` = `"OrgA"`, fetches `OrgA`'s app, and the signature validates successfully. [1](#0-0) [2](#0-1) 
5. `PushHandler` (via `Handler#repository_name`) resolves `"OrgB/victim-repo"` and calls `stack.sync_github` on `OrgB`'s stacks, despite the request never being signed by `OrgB`. [3](#0-2) [10](#0-9)

### Citations

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end
```
