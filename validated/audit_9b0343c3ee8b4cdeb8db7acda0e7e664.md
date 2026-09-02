### Title
Webhook signature verified against payload's `repository.owner.login` while event processing trusts a separate, unvalidated `repository.full_name` / commit `sha` field, allowing cross-organization status/sync forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization secret to verify the HMAC signature against using `repository_owner`, taken from `params.dig('repository', 'owner', 'login')` (or `organization.login`). [1](#0-0) [2](#0-1)  Once the signature check passes, the actual event handlers resolve which repository/stack/commit to act on using a *different* field of the same attacker-supplied JSON body: `payload.dig('repository', 'full_name')` in `Handler#repository_name` (used by `PushHandler`), or the bare `sha` in `StatusHandler`, which is not scoped to any repository at all. [3](#0-2) [4](#0-3)  There is no check anywhere that the org used to authenticate the request matches the repository or commit the handler subsequently mutates.

### Finding Description
The bug-class analog is the same as the go-f3 report: a value used for validation (`repository.owner.login`, analogous to the signer index) is disjoint from the value the code actually acts on (`repository.full_name` / bare commit `sha`, analogous to the justification power field), and nothing binds them together.

- `verify_signature` fetches `Shipit.github(organization: repository_owner)` and checks the `X-Hub-Signature` HMAC against that organization's `webhook_secret`. [5](#0-4) 
- After the signature check succeeds, `create` simply dispatches the raw, attacker-controlled JSON body to the handler for the event type: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. [6](#0-5) 
- `PushHandler` resolves the target stacks via `Repository.from_github_repo_name(repository_name)`, where `repository_name` comes from `payload.dig('repository', 'full_name')` — a field that is never compared against `repository.owner.login` used for signing. [3](#0-2) [7](#0-6) 
- `StatusHandler` is even less scoped: it looks up `Commit.where(sha: params.sha)` globally across the entire Shipit instance (no repository filter at all) and calls `commit.create_status_from_github!(params)` for every matching commit, potentially across unrelated stacks belonging to different organizations. [4](#0-3) 

Equality that should hold but doesn't:
`organization authenticated by verify_signature (repository.owner.login)` == `organization/repository whose state the handler mutates (repository.full_name / commit.sha)`

Before the attacker's request: an org's webhook secret only lets GitHub-originated events for that org's own repositories reach handlers, because in normal operation `repository.owner.login` and `repository.full_name`'s owner are always identical (GitHub sets both consistently). After the attacker's crafted request: the attacker signs the payload with a secret they legitimately possess (e.g., the webhook secret for their own org/repo tracked by the same Shipit instance, obtained by configuring a repo they control), sets `repository.owner.login` to their own org (so `verify_signature` passes), but sets `repository.full_name` (for push) or `sha` (for status) to reference a victim organization's stack/commit that they do not control.

### Impact Explanation
- Via `StatusHandler`, an attacker who owns (or controls) any single organization/repository connected to the same Shipit instance can forge a `status` webhook with `state: "success"` for an arbitrary commit `sha` belonging to a completely unrelated victim stack, since the handler applies no repository scoping. [8](#0-7)  If deploy eligibility or required-status gating in the merge/deploy flow relies on stored `Status` records, this can be used to fake CI green checks and push a stack toward an unauthorized deploy/merge.
- Via `PushHandler`, the attacker can force `GithubSyncJob` to run against a victim stack with an attacker-chosen `expected_head_sha`. [7](#0-6)  The job itself re-fetches real commits from GitHub via `stack.github_commits` using the stack's own credentials, so it does not directly inject forged commit content — `expected_head_sha` is only used for retry/consistency logic. [9](#0-8)  This narrows the push-handler variant to a forced-trigger issue rather than data injection.
- The `StatusHandler` path is the more serious one because it crosses a repository/organization trust boundary to write state (a commit status) for a stack outside the authenticating organization, which can influence deploy/merge authorization decisions downstream.

### Likelihood Explanation
Exploitability requires only that the attacker control any organization/repository already registered with the target Shipit instance (i.e., they have a legitimate `GithubHook`/webhook secret for their own repo, not the victim's). No Shipit session, `ApiClient` token, or GitHub App private key is needed. Since Shipit instances commonly host many organizations/repos as tenants, this is a realistic, low-barrier attack for anyone with write access to one of the tracked orgs.

### Recommendation
In `Shipit::WebhooksController` and/or `Shipit::Webhooks::Handlers::Handler`, validate that the organization/owner used to select the signature-verification secret is the same owner embedded in the fields each handler subsequently acts on (`repository.full_name`'s owner segment for push/check_suite, and the resolved commit's stack owner for status events) before dispatching to handlers. For `StatusHandler` specifically, scope `Commit.where(sha:)` to commits whose stack's repository owner matches the authenticated `repository_owner`, rejecting the event otherwise.

### Proof of Concept
1. Attacker controls org `attacker-org`, which has a real Shipit `GithubHook` with a known `webhook_secret`.
2. Attacker crafts a `status` event payload:
```json
{
  "sha": "<victim-stack-commit-sha>",
  "state": "success",
  "context": "ci/build",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/some-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac using attacker-org's webhook secret>` over the raw body and POSTs it to `/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and the signature validates successfully because it was signed with `attacker-org`'s real secret. [5](#0-4) 
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — which matches the victim's commit in an unrelated stack — and calls `create_status_from_github!`, writing a forged "success" status onto it. [4](#0-3)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
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
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/jobs/shipit/github_sync_job.rb (L18-42)
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
```
