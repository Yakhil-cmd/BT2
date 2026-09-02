### Title
Webhook signature is verified against the wrong tenant's secret because organization authentication and the target repository are read from different, independently-attacker-controllable fields of the same unauthenticated payload - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks the GitHub App/webhook secret to check the HMAC against based on `repository.owner.login`, while every webhook `Handler` (push, pull_request, status, etc.) resolves the `Stack`/`Repository` it actually mutates using `repository.full_name`. These are two independent JSON fields in the same POST body, and nothing ties them together, so a signature that is valid for tenant A's secret can be replayed with a `full_name` pointing at tenant B's repository.

### Finding Description
`verify_signature` computes the organization used to look up the webhook secret from the payload itself, not from any authenticated channel: [1](#0-0) [2](#0-1) 

```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
`verify_signature` then does `Shipit.github(organization: repository_owner)` and checks `X-Hub-Signature` against `request.raw_post` with that organization's `webhook_secret`: [3](#0-2) 

But every handler resolves the repository/stack to mutate using a completely different field, `repository.full_name`: [4](#0-3) 

`PushHandler` (and the pull_request/status handlers analogously) use that `stacks` helper directly, then act on whatever stack is found: [5](#0-4) 

Since the webhooks endpoint is unauthenticated (only HMAC-protected) and mounted for arbitrary POSTs (`skip_before_action :verify_authenticity_token`) [6](#0-5) , any party who legitimately knows one tenant's webhook secret (e.g., they administer their own GitHub org that is integrated with this shared Shipit instance, per the multi-org config shown in `config/secrets.development.shopify.yml`) can craft a raw POST body where `repository.owner.login` is their own org (so `verify_signature` succeeds against their own known secret) while `repository.full_name` names a stack/repository belonging to a *different* org that is also configured on the same Shipit instance. The equality that should hold — "organization whose secret authenticated the request" == "repository that gets written by the handler" — is broken because the two values are read from unrelated, unsigned-in-the-cryptographic-binding-sense JSON keys that GitHub itself keeps consistent, but this endpoint does not.

### Impact Explanation
This lets an attacker who only controls one tenant's webhook secret trigger `Handlers::Handler#stacks` / `PushHandler#process` for a stack belonging to a different, unrelated repository on the same shared instance [4](#0-3) [7](#0-6) . For `push`, this enqueues `stack.sync_github(expected_head_sha: params.after)`, which schedules `GithubSyncJob` to re-fetch commits from the real GitHub API and, if new commits are appended, can drive continuous-delivery/auto-deploy logic for a stack the attacker has no legitimate authority over [8](#0-7) . Other handlers (pull_request opened/labeled/closed, status) similarly resolve `repository` via `full_name` and can archive/unarchive review stacks or record spoofed commit statuses for a victim repository/organization that the attacker does not administer.

### Likelihood Explanation
Exploitability requires only that the attacker legitimately control one tenant's webhook configuration on a shared, multi-organization Shipit deployment (as the shipped `secrets.development.shopify.yml` demonstrates is a supported topology) — no Shipit session, `ApiClient` token, or GitHub write access to the victim repository is required. The endpoint accepts arbitrary raw POST bodies and only checks the HMAC of the whole body against a secret chosen from a field inside that same body, so the cross-tenant confusion is directly reachable from the public webhook endpoint.

### Recommendation
Bind the webhook secret lookup and the handler's repository resolution to the same, single source of truth (ideally the same field, or cross-check that `repository.owner.login` matches the owner of `repository.full_name` before dispatching to handlers). Alternatively, look up the target `Repository`/`Stack` first, derive its expected organization from stored configuration, and reject the webhook if the signature-selected organization does not match the organization that owns the resolved repository.

### Proof of Concept
1. Configure Shipit with two tenants, `orgA` (attacker-administered, webhook secret `sA` known to attacker) and `orgB` (victim), per `config/secrets.development.shopify.yml`.
2. Attacker crafts a JSON body for the `push` event: `{"ref": "refs/heads/master", "after": "<attacker-chosen sha>", "repository": {"owner": {"login": "orgA"}, "full_name": "orgB/victim-repo"}}`.
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(sA, body)>` using the known `orgA` secret and POSTs to `/webhooks` with header `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "orgA")`, verifies successfully against `sA` [3](#0-2) .
5. `PushHandler.call(params)` resolves stacks via `repository.full_name` = `"orgB/victim-repo"` [4](#0-3)  and calls `stack.sync_github(expected_head_sha: ...)` for the victim's stack, triggering an unauthorized sync/deploy pipeline for `orgB`'s repository, despite the attacker having no relationship to `orgB`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L1-6)
```ruby
# frozen_string_literal: true

module Shipit
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-24)
```ruby
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

**File:** app/jobs/shipit/github_sync_job.rb (L18-48)
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
```
