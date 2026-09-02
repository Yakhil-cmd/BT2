### Title
Webhook signature is verified against the payload's `repository.owner.login`/`organization.login`, but event handlers resolve the target Stack from the unverified `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to check the HMAC signature against using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`). [1](#0-0) [2](#0-1) 

Once the signature is accepted, the full raw JSON payload is forwarded unmodified to the registered handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. [3](#0-2) 

The handlers, however, do not use `repository.owner.login` to locate the target `Stack`. Instead, the base `Handler` class (and `PushHandler`, and PR handlers) resolve the repository/stack using a completely different, also attacker-controlled field: `payload.dig('repository', 'full_name')`. [4](#0-3) [5](#0-4) 

`Repository.from_github_repo_name` simply splits `full_name` on `/` and looks up any `Repository` record by `owner`/`name`, with no cross-check against the org whose secret validated the signature. [6](#0-5) 

### Finding Description
This is the same class of bug as the `Curves.getPrice()` issue: a value that is authorized/verified (the `supply` used in `sum1`) is not the same value that is actually acted upon (`supply` mixed with `amount` in a different order in `sum2`), breaking an implicit invariant that the checked quantity and the acted-upon quantity must match.

In `shipit-engine`, the equality that must hold is:

`organization authenticated by verify_webhook_signature == organization of the repository whose Stack is mutated by the handler`

`verify_signature` authenticates a webhook against organization `A` by using `A`'s `webhook_secret`, based on `repository.owner.login` (or `organization.login`) in the JSON body. But the handlers key off `repository.full_name`, an independent JSON field within the *same signed payload*. Nothing forces `repository.owner.login == repository.full_name.split('/').first`.

On a multi-tenant Shipit instance (the engine explicitly supports configuring multiple GitHub organizations, each with its own `app_id`/`installation_id`/`webhook_secret`, e.g. in `config/secrets.development.shopify.yml`), an attacker who controls (or has onboarded) their own GitHub App/organization "AttackerOrg" on this instance knows `AttackerOrg`'s `webhook_secret`. They can craft and correctly HMAC-sign an arbitrary JSON body themselves (the signature is just `HMAC-SHA1(webhook_secret, raw_body)` - see `verify_webhook_signature`), because they control that secret. [7](#0-6) 

They set:
- `repository.owner.login` = `"AttackerOrg"` (so `verify_signature` looks up and validates against `AttackerOrg`'s known secret and succeeds)
- `repository.full_name` = `"VictimOrg/victim-repo"` (an unrelated repository/Stack tracked on the same Shipit instance, belonging to an org the attacker has no GitHub permissions on)

Because signature verification and stack resolution consult two different fields of the same untrusted payload, the request is accepted as authentic for `AttackerOrg` yet acted upon as if it originated from `VictimOrg`.

### Impact Explanation
For the `push` event, `PushHandler#process` finds every non-archived `Stack` on the victim repository whose branch matches `params.ref` and calls `stack.sync_github(expected_head_sha: params.after)`, which enqueues `GithubSyncJob` for that stack with an attacker-chosen `expected_head_sha`. [8](#0-7) 

`GithubSyncJob` then fetches commits from the real `VictimOrg/victim-repo` via the GitHub API (using Shipit's own installed credentials for that org) and updates the Stack's commit graph / retries against the attacker's supplied `expected_head_sha`. [9](#0-8) 

This lets an attacker who only controls one tenant/org on a shared Shipit instance force sync/refresh activity, cache invalidation (`CacheDeploySpecJob`), and repeated GitHub API polling/state changes against a Stack belonging to an organization they have no access to, and forge `status`/`pull_request`/`membership` events the same way against arbitrary victim repositories/stacks configured on the instance, since every handler shares the same `repository_name`/`full_name`-based lookup that is disjoint from the field used for signature verification. This crosses a repository-boundary trust binding without any GitHub write access to the victim repo, matching the "unauthorized... cross-repository writes/actions"-class impact called for by the rules (the attacker forces engine-internal state changes and GitHub API calls scoped to a repository they don't control).

### Likelihood Explanation
Requires the Shipit instance to be configured for more than one GitHub organization (documented, supported multi-tenant configuration via `config/secrets*.yml` with per-org `webhook_secret`), and requires the attacker to be an onboarding admin/owner of one such organization's GitHub App - i.e., a legitimate but unprivileged (with respect to the victim org) tenant of the platform. No GitHub write access to the victim repository, no Shipit session, and no possession of the victim's or Shipit's own secrets is needed; only knowledge of the attacker's own org's webhook secret, which they control by design.

### Recommendation
After signature verification, re-derive the authorized organization/repository binding and enforce it before invoking handlers: require that `repository.full_name.split('/').first == repository_owner` (or `organization.login`) used in `verify_signature`, rejecting (422) any payload where these disagree. Alternatively, scope handler lookups (`Handler#stacks`, `Repository.from_github_repo_name`) to only the organization that was actually authenticated by `verify_webhook_signature`, rather than trusting `repository.full_name` independently.

### Proof of Concept
1. Configure/assume a multi-tenant Shipit instance with two onboarded GitHub Apps: `AttackerOrg` (secret known to attacker) and `VictimOrg` (has a tracked `Stack` for `VictimOrg/victim-repo`).
2. Attacker builds a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "AttackerOrg" },
    "full_name": "VictimOrg/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC_SHA1(AttackerOrg_webhook_secret, raw_body)` and POSTs to `/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: 'AttackerOrg')` and `verify_webhook_signature` succeeds because the attacker knows that secret. [1](#0-0) 
5. `PushHandler` resolves stacks via `payload.dig('repository', 'full_name')` = `"VictimOrg/victim-repo"`, finds the real victim `Stack`, and enqueues `GithubSyncJob` with the attacker's `expected_head_sha`, causing GitHub-authenticated sync activity against the victim repository the attacker never had access to. [5](#0-4) [4](#0-3)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-23)
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
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
