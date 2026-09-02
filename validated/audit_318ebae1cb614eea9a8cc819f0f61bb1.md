### Title
Webhook signature is verified against `repository.owner.login`-derived secret while push/pull-request handlers act on the independent `repository.full_name` field, allowing cross-organization forgery of sync/deploy-triggering events - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: app/models/shipit/webhooks/handlers/push_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret used to authenticate an inbound GitHub webhook based on the `repository.owner.login` (or `organization.login`) field taken directly from the untrusted JSON payload, then validates the raw body against that org's `webhook_secret`. [1](#0-0) [2](#0-1)  Once the signature is accepted, event handlers such as `PushHandler` (and every PR handler) resolve the target `Repository`/`Stack` using an entirely different payload field, `repository.full_name`, via `Repository.from_github_repo_name`. [3](#0-2) [4](#0-3)  Nothing enforces that the organization named in `repository.owner.login` (used for authentication) matches the organization encoded in `repository.full_name` (used for authorization/action). This breaks the binding: `organization authenticated == organization acted upon`.

### Finding Description
`GitHubApp#verify_webhook_signature` simply HMACs the raw body with whatever secret is configured for the organization passed to it: `return true unless webhook_secret; ... SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))`. [5](#0-4)  The org used to fetch that secret comes straight from the attacker-controlled payload:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [6](#0-5) 

In a multi-org Shipit installation (which the engine explicitly supports — each org has its own `app_id`/`installation_id`/`webhook_secret` entry, see `config/secrets.development.shopify.yml`), an attacker who legitimately controls (or is a member with webhook-configuration rights on) one onboarded organization "A" knows/owns A's `webhook_secret` and can therefore produce a **valid** HMAC signature for any payload they craft, as long as `repository.owner.login` (or `organization.login`) is set to `"A"`.

However, the actual object acted upon by the event handler is picked independently, from `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

`Repository.from_github_repo_name` just splits the string on `/` and looks the repo up by `owner`/`name` columns with no cross-check against the field used for signature verification: `repo_owner, repo_name = github_repo_name.downcase.split('/'); find_by(owner: repo_owner, name: repo_name)`. [7](#0-6) 

So an attacker who controls org "A" (onboarded to this Shipit instance) can send a forged `push` webhook, signed with A's secret, where:
- `repository.owner.login = "A"` (satisfies the signature check),
- `repository.full_name = "B/victim-repo"` (a stack belonging to a different onboarded org "B" that the attacker has no rights on).

`PushHandler#process` will then look up stacks for `B/victim-repo`, filter by `branch`, and call `stack.sync_github(expected_head_sha: params.after)` for each matching stack. [8](#0-7)  That enqueues `GithubSyncJob` which fetches commits via `stack.github_commits`/`github_api` (using org B's real, legitimate GitHub App credentials, since `Repository#github_app` resolves via the DB-stored `owner` — org B — not the attacker's org), and appends new commits: [9](#0-8) [10](#0-9) [11](#0-10) 

The same class of mismatch affects all PR handlers (`OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `EditedHandler`, `LabelCapturingHandler`, etc.), which likewise resolve `repository` via `params.repository.full_name` while the controller authenticated the request against `repository.owner.login`. [12](#0-11) 

Before/instead binding:
- Before: `authenticated_org(payload.repository.owner.login) == acted_upon_org(derived from payload.repository.full_name)` is assumed but never enforced.
- After (attacker PR/request): attacker sets `repository.owner.login = "A"` (their org) and `repository.full_name = "B/victim-repo"` (target org's repo), breaking the equality while still passing signature verification.

### Impact Explanation
This allows an attacker who onboards or compromises a webhook secret for one organization in a multi-tenant Shipit deployment to forge GitHub events (push, pull_request open/close/reopen/label, etc.) that Shipit will process as if they came from GitHub for an *unrelated* organization/repository they do not control. Concretely this can:
- Force `GithubSyncJob` to run against a victim stack, causing continuous-deployment-enabled stacks to pull and potentially auto-deploy attacker-influenced state depending on `expected_head_sha`/branch matching, i.e. an unauthorized deploy trigger.
- Archive/unarchive review stacks, or otherwise manipulate lifecycle state of a victim's stacks/PR review environments via the PR handlers, since those also key off `repository.full_name` alone.
This matches the "unauthenticated read/write of stack state" / "unauthorized deploy" impact bar since the org whose credentials authenticate the webhook is not the org whose stack is mutated.

### Likelihood Explanation
Likelihood is High in any multi-organization Shipit installation (a documented, supported configuration — see `config/secrets.development.shopify.yml` and `docs/setup.md`), since the org-selection logic for signature verification is entirely payload-driven and no additional binding check exists in `WebhooksController` or in `Handler`/`PushHandler`. Any actor who legitimately administers one onboarded GitHub org's webhook (an "unprivileged attacker" relative to other tenants of the same Shipit instance) can exploit this without any Shipit session or API token.

### Recommendation
After computing `repository_owner` for signature verification, re-derive the organization from `repository.full_name` (or `organization.login` for org-level events) and require they match before dispatching to handlers; alternatively, have handlers verify that `Repository#owner` matches the already-authenticated `repository_owner` from the controller before acting, e.g.:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  head(422) unless verified

  full_name_owner = params.dig('repository', 'full_name')&.split('/')&.first
  head(422) if full_name_owner && full_name_owner.casecmp(repository_owner).nonzero?
end
```

### Proof of Concept
1. Shipit is configured with two organizations, `attacker-org` and `victim-org`, each with its own `webhook_secret` (a supported, documented multi-org config, see `config/secrets.development.shopify.yml`).
2. Attacker, who administers a GitHub App/webhook for `attacker-org`, knows `attacker-org`'s `webhook_secret`.
3. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "attacker-org" }
  }
}
```
4. Attacker computes `sha1=HMAC(attacker-org_webhook_secret, body)` and POSTs to `/webhooks` with `X-Github-Event: push` and `X-Hub-Signature` set to that value.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` and verifies successfully against `attacker-org`'s secret. [1](#0-0) 
6. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` for the victim's stack, using the victim org's own GitHub App credentials to sync. [8](#0-7)

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/repository.rb (L98-102)
```ruby
    protected

    def github_app
      Shipit.github(organization: owner)
    end
```

**File:** app/jobs/shipit/github_sync_job.rb (L18-53)
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

    def append_commit(gh_commit)
      stack.commits.create_from_github!(gh_commit)
    end
```

**File:** app/models/shipit/stack.rb (L612-614)
```ruby
    def sync_github(expected_head_sha: nil)
      GithubSyncJob.perform_later(stack_id: id, expected_head_sha:)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
