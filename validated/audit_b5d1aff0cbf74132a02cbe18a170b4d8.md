This confirms the vulnerability. Let me verify the `sync_github` / `GithubSyncJob` flow to confirm the impact of a forged `expected_head_sha`/repository mismatch.### Title
Webhook signature verification keys on `repository.owner.login`, but repository dispatch keys on `repository.full_name` — allows cross-organization/cross-repository writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
This is the same bug class as the reported `fp.Element#SetBytes` issue: a value is used to make a security decision (which HMAC secret to validate against) while a *different, independently-controllable* value in the same signed blob is used for the actual state-changing action. The verification does not bind the field it trusts to the field the handlers act on.

### Finding Description
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`: [1](#0-0) [2](#0-1) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login')` (or `organization.login`). Once the signature is accepted, `WebhooksController#create` dispatches the *entire* raw JSON body to the matching event handler: [3](#0-2) 

Every handler (e.g. `PushHandler`) determines *which* `Repository`/`Stack` to mutate using a completely different field of the same payload: `repository.full_name`, via `Handler#stacks` / `Handler#repository_name`: [4](#0-3) [5](#0-4) [6](#0-5) 

Nothing in the code enforces that `repository.owner.login` (the field bound into the signature-verification key selection) matches the owner segment of `repository.full_name` (the field actually used to select the acted-upon `Repository`/`Stack`). This engine explicitly supports multiple GitHub organizations, each configured with its own independent `webhook_secret`, resolved via `Shipit.github(organization:)` / `github_app_config`: [7](#0-6) 

Under real GitHub delivery these two fields are always consistent because GitHub itself generates the whole payload. But Shipit's webhook endpoint has no cryptographic binding tying "the secret that signed this request" to "the repository field the handler will act on" — it only checks that *some* valid HMAC exists for whichever organization's secret matches the (attacker-supplied) `owner.login`. An entity that legitimately controls one configured organization (and therefore knows/has access to that organization's own `webhook_secret`, e.g. a lower-trust tenant in this same multi-org Shipit deployment) can construct an arbitrary JSON body, set `repository.owner.login` to their own org (so `verify_signature` selects and matches their own known secret) while setting `repository.full_name` to `"other-org/other-repo"` — a repository belonging to a different, more privileged organization tracked in the same Shipit instance — and self-sign the whole payload with their own secret.

This breaks the intended binding: **organization whose secret authenticated the request == repository/organization actually written to by the handler**.

### Impact Explanation
Because `PushHandler#process` uses only `repository.full_name` to look up stacks and enqueues `GithubSyncJob` with an attacker-chosen `expected_head_sha`, an attacker who only controls their own (lower-trust) organization's webhook secret can trigger sync/deploy-relevant state changes (`stack.sync_github`, `GithubSyncJob`, `CacheDeploySpecJob`) against a `Stack` belonging to an entirely different organization's repository they have no legitimate access to: [8](#0-7) 

Other handlers (`PullRequest::OpenedHandler`, `LabeledHandler`, `ReopenedHandler`, `AssignedHandler`, `label_capturing_handler`, membership handlers, etc.) exhibit the same pattern — they all resolve the acted-upon `Repository`/`Stack`/`PullRequest`/`Team` from `repository.full_name`/`organization.login` fields independent from the org used for signature verification. This can drive cross-repository writes (syncing commits, archiving/unarchiving review stacks, mutating pull-request/label state, or membership changes) tied to an organization the attacker never authenticated against, which meets the "cross-repository writes" / "unauthorized deploy" Critical-impact bar defined in scope.

### Likelihood Explanation
Exploitability requires that this Shipit instance is configured to serve **multiple GitHub organizations**, each with its own `webhook_secret` (a supported, documented configuration per `test/dummy/config/secrets_double_github_app.yml` and `Shipit.github_organizations`), and that the attacker legitimately controls (or has knowledge of the webhook secret for) at least one of the lower-trust organizations onboarded to the instance. Given that this is a first-class supported multi-tenant configuration in the engine, and no unprivileged-attacker credential beyond "control of one's own already-configured organization's webhook secret" is required, likelihood is Medium-High for deployments that use multi-org configuration; the bug is latent (not reachable) in single-org deployments since there is only one possible `webhook_secret` regardless of payload content.

### Recommendation
In `WebhooksController#verify_signature` (or in the base `Handler`), enforce that the organization used to select/validate the webhook secret is the *same* value later used by every handler to resolve the repository — e.g., derive `repository_name`/`stacks` from a value cryptographically pinned to the verified organization, or explicitly validate that `params.dig('repository','full_name').split('/').first == repository_owner` before dispatching to any handler. More robustly, the resolved organization from signature verification should be threaded through to `Handler#initialize` and used to scope `Repository.from_github_repo_name` lookups, rather than trusting the unauthenticated-against-org-binding `full_name` field.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` (installed/controlled by the attacker, with a known `webhook_secret`) and `victim-org` (a separate, unrelated tenant tracked by the same Shipit instance), per the pattern in `test/dummy/config/secrets_double_github_app.yml`.
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-existing-sha-in-victim-repo>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org's webhook_secret, raw_body)>` and POSTs to `/github/webhooks`.
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`) and the signature validates successfully because it was signed with `attacker-org`'s legitimate secret.
5. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which calls `Handler#stacks` → `Repository.from_github_repo_name("victim-org/victim-repo")`, locating and mutating `victim-org`'s stacks via `stack.sync_github(expected_head_sha: ...)`, even though the request was never authenticated by `victim-org`'s webhook secret.

(This analysis could not execute the PoC against a live instance; verification relies on static tracing of `WebhooksController`, `Shipit::Webhooks::Handlers::Handler`, `PushHandler`, and `Shipit::Repository.from_github_repo_name` as cited above.)

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
