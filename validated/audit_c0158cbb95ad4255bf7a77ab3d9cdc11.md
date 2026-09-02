### Title
Webhook signature verification authenticates a different field than the one used to select the target repository/stack - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate `X-Hub-Signature` against using `repository_owner`, which is read from `payload.dig('repository', 'owner', 'login')`. Every webhook handler, however, resolves the actual `Repository`/`Stack` to act on using a *different* field of the same JSON object: `payload.dig('repository', 'full_name')` (via `Handler#repository_name`). Because HMAC verification only proves that *some* configured organization's secret produced a valid signature for the raw body, and the field used to pick *which* organization's secret to check (`owner.login`) is not cross-checked against the field used to pick *which repository/stack gets mutated* (`full_name`), an attacker who legitimately controls one onboarded GitHub organization can craft a payload whose `repository.full_name` names a stack belonging to a completely different organization hosted on the same Shipit instance.

### Finding Description
Signature verification: [1](#0-0) [2](#0-1) 

`repository_owner` is derived purely from `repository.owner.login` (or the `organization.login` fallback). `Shipit.github(organization: repository_owner)` picks the per-organization app config (and its `webhook_secret`) declared in `config/secrets.yml`, e.g.: [3](#0-2) 

Every handler resolves its target repository from an entirely separate key of the *same* `repository` object: [4](#0-3) 
For example the push handler, which triggers a resync of any matching stack: [5](#0-4) 

Nothing enforces `repository.owner.login == repository.full_name.split('/').first`. Since the raw HMAC signature only proves the payload bytes were produced with organization X's secret (a value the requester who administers/owns org X's installed GitHub App legitimately possesses, e.g. by triggering a real webhook delivery from their own repo and replaying/mutating fields before forwarding, or by directly signing an arbitrary body offline with a secret they know for their own org), the equality that should hold is:

`organization authenticated by verify_signature (repository.owner.login → webhook_secret) == repository/stack actually mutated by the handler (repository.full_name)`

This equality is never checked. An attacker who is a legitimate admin of one Shipit-integrated GitHub organization (attacker-org) can compute a valid `X-Hub-Signature` for a JSON body where `repository.owner.login = "attacker-org"` (so `verify_signature` picks and successfully checks the attacker-org secret) while `repository.full_name = "victim-org/victim-repo"` (the field every handler actually uses to look up `Repository`/`Stack`). The signature check passes for a payload it was never meant to authorize against the victim organization's data.

### Impact Explanation
Handlers reachable this way include `PushHandler`, which enqueues `GithubSyncJob` against any stack matching `full_name`+branch: [6](#0-5) 
This fetches new commits from GitHub for the victim stack and appends them, invalidates/regenerates the cached deploy spec, and can feed continuous-delivery/auto-deploy logic on `Stack`/`Commit` (I was not able to fully trace the auto-deploy trigger chain from `append_commit`/`CacheDeploySpecJob` within the remaining budget, so this specific downstream consequence is not fully confirmed). Other handlers (`MembershipHandler`, pull-request handlers, `StatusHandler`) similarly key off `repository.full_name` to mutate `PullRequest`, `Commit`/`Status`, and stack archival state for a repository outside the authenticating organization's control. At minimum this is a cross-repository/cross-organization write of Shipit-managed state (commit/status ingestion, stack archive/unarchive, PR label capture) driven by a signature that never covered the targeted repository — meeting the "cross-repository writes" bar.

### Likelihood Explanation
Requires the attacker to control/administer at least one GitHub organization already onboarded to the same multi-org Shipit deployment (so they legitimately know or can trigger valid signatures for that org's `webhook_secret`), and knowledge that a victim stack with a colliding branch/full_name exists on the same instance. This is plausible in any multi-tenant Shipit deployment configured with the multi-org `github:` secrets layout shown in `config/secrets.development.shopify.yml`, where multiple orgs share one Shipit instance but each has its own webhook secret — exactly the scenario the config format is designed to support.

### Recommendation
In `WebhooksController#verify_signature`, after verifying the HMAC, also assert that `repository.owner.login` (used to pick the app/secret) matches the owner segment of `repository.full_name` (used by every `Handler` subclass) before dispatching to `Shipit::Webhooks.for_event(event)`. Alternatively, have `Handler#repository_name` derive the repository solely from `repository.owner.login` + `repository.name` rather than trusting `full_name` independently, so the field verified and the field acted upon are provably the same value.

### Proof of Concept
1. Attacker is a legitimate admin of `attacker-org`, which is configured in this Shipit instance's `config/secrets.yml` with its own `webhook_secret`.
2. Attacker crafts a JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac>` using `attacker-org`'s known `webhook_secret` over this exact raw body (per `Shipit::GithubApp#verify_webhook_signature`, `app/controllers/shipit/webhooks_controller.rb:24-30` and `lib/shipit/github_app.rb:76-83`).
4. POST to `/webhooks` with `X-Github-Event: push`. `verify_signature` calls `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`) and the signature validates successfully.
5. `PushHandler#process` resolves `stacks` via `repository_name = payload.dig('repository','full_name')` = `"victim-org/victim-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`), locates the victim stack, and enqueues `GithubSyncJob` for it — a repository the attacker was never authorized to touch — despite the signature being valid only for `attacker-org`.

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
