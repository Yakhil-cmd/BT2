### Title
Webhook signature bypass allows cross-organization event forgery when any configured GitHub org has no `webhook_secret` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/secret to validate a webhook against using one payload field (`repository.owner.login` / `organization.login`), while the event handlers that actually act on the webhook use a *different* payload field (`repository.full_name`). Because `GitHubApp#verify_webhook_signature` short-circuits to `true` when no `webhook_secret` is configured for the selected organization, an attacker who knows (or guesses) the login of *any* org configured on the Shipit instance without a `webhook_secret` can submit a completely unsigned webhook whose `repository.full_name` field points at a *different, properly-configured* org/repo, and have it processed as authentic.

### Finding Description
Signature verification and payload interpretation are bound to two different fields:

- Verification org selection: `repository_owner` in `app/controllers/shipit/webhooks_controller.rb` reads `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` and passes it to `Shipit.github(organization: repository_owner)` to pick a `GitHubApp` config, then calls `verify_webhook_signature`. [1](#0-0) [2](#0-1) 

- Signature check bypass: `verify_webhook_signature` in `lib/shipit/github_app.rb` returns `true` unconditionally when `webhook_secret` is blank for that org's config. [3](#0-2) 

- Downstream, event handlers such as `Shipit::Webhooks::Handlers::Handler` and `PushHandler` resolve the target repository/stack from `payload.dig('repository', 'full_name')` — a field that is completely unrelated to (and not covered by) the org used for signature verification. [4](#0-3) [5](#0-4) 

The binding that should hold is: `organization authenticated (via webhook_secret) == repository/organization the handlers act on`. This equality is broken because:
1. The webhook secret configured per-org is optional (`webhook_secret: # nil` is a documented/sample configuration value in `config/secrets.development.shopify.yml` and `docs/setup.md`), and when unset, `verify_webhook_signature` returns `true` for *any* payload with *any* content — effectively disabling authentication for that org's namespace entirely.
2. The org chosen for this (now-vacuous) check is taken from `repository.owner.login`/`organization.login`, while the actual repo/stack acted upon by every handler is taken from `repository.full_name`, a sibling field in the same attacker-controlled JSON body.

Consequently, if the Shipit instance manages multiple GitHub orgs and any one of them (`OrgB`) is configured without a `webhook_secret` — while another org (`OrgA`) is properly secured — an attacker can send an unsigned POST to `/webhooks` with `repository.owner.login = "OrgB"` (or `organization.login = "OrgB"`) but `repository.full_name = "OrgA/some-repo"`. The signature check passes trivially (no secret registered for OrgB), and the handler then operates on `OrgA/some-repo` using entirely attacker-supplied event data (e.g. forged `push` `after` SHA, forged `status`/`check_suite` state, forged `pull_request` open/close/label events), even though OrgA's webhook is properly secured and was never contacted.

### Impact Explanation
This breaks the authentication boundary between organizations sharing one Shipit deployment: possessing zero secrets for the "weak" org is sufficient to forge trusted GitHub events for a completely different, "strong" org's repositories. Depending on which handler is reached this can:
- Force `Stack#sync_github` for arbitrary commits/branches via `PushHandler` [6](#0-5) , corrupting commit/deploy state used later to gate deploys.
- Forge CI `status`/`check_suite` results that feed into deployability and the merge queue, which can unblock automatic merges/deploys performed by `ProcessMergeRequestsJob#merge!` (which calls the GitHub API with the app's own credentials to merge PRs) [7](#0-6) [8](#0-7) .
- Manipulate review-stack provisioning/archival via the `pull_request` handlers, which act purely on `params.repository.full_name` without any tie-back to the org that was actually authenticated [9](#0-8) .

This can lead to unauthorized merges/deploys being triggered against a repository the attacker does not control, satisfying the "unauthorized deploy, rollback or merge" Critical impact bar, without needing any `ApiClient` token, Shipit session, or privileged GitHub account — the request goes straight to the public, unauthenticated `POST /webhooks` route [10](#0-9) .

### Likelihood Explanation
Likelihood is conditional: it requires the specific operator misconfiguration of at least one configured GitHub org lacking a `webhook_secret` while other orgs on the same instance are secured. This is an explicitly supported, documented configuration shape (multiple orgs configured under `github:` in secrets, with `webhook_secret` shown as optional/nilable in both the sample dev config and `docs/setup.md`), so it is a realistic deployment pattern for larger organizations onboarding multiple GitHub orgs incrementally, rather than a purely theoretical edge case. The root cause is a genuine code defect (verification keyed off one field, authorization enforcement effectively keyed off another, unrelated field) rather than a documented, intentional trust decision.

### Recommendation
- Do not allow `verify_webhook_signature` to silently return `true` when `webhook_secret` is unset; instead fail closed (reject the webhook) unless the operator has explicitly opted into an "insecure" mode for that org, and warn loudly in that case.
- Cross-check that the organization used to select the verification secret matches the owner/org embedded in the field the handlers actually consume (`repository.full_name`'s owner segment), rejecting payloads where they diverge.
- Consider requiring a `webhook_secret` for every configured GitHub org, or enforce a global/default secret fallback rather than a fully-unauthenticated fallback per org.

### Proof of Concept
1. Configure a Shipit instance with two orgs: `OrgA` (has `webhook_secret` set) and `OrgB` (has `webhook_secret` left blank/nil), matching the documented format in `config/secrets.development.shopify.yml`.
2. As an unauthenticated attacker, send:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything-or-empty

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgB" },
    "full_name": "OrgA/some-real-secured-repo"
  }
}
```
3. `WebhooksController#repository_owner` resolves to `OrgB`; `Shipit.github(organization: "OrgB").verify_webhook_signature(...)` returns `true` immediately because `OrgB` has no `webhook_secret` (`lib/shipit/github_app.rb:76-83`), regardless of the signature header or body content.
4. `PushHandler#process` then runs against `Repository.from_github_repo_name("OrgA/some-real-secured-repo")`'s stacks (`app/models/shipit/webhooks/handlers/handler.rb:32-38`), triggering `sync_github(expected_head_sha: <attacker-chosen sha>)` on `OrgA`'s stack — despite `OrgA`'s webhook secret never being presented or validated.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/jobs/shipit/process_merge_requests_job.rb (L10-31)
```ruby
    def perform(stack)
      merge_requests = stack.merge_requests.to_be_merged.to_a
      merge_requests.each do |merge_request|
        merge_request.refresh!
        merge_request.reject_unless_mergeable!
        merge_request.cancel! if merge_request.closed?
        merge_request.revalidate! if merge_request.need_revalidation?
      end

      return false unless stack.allows_merges?

      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
        rescue MergeRequest::NotReady
          ProcessMergeRequestsJob.set(wait: 10.seconds).perform_later(stack)
          return false
        end
      end
```

**File:** app/models/shipit/merge_request.rb (L164-176)
```ruby
    def merge!
      raise InvalidTransition unless pending?

      raise NotReady if not_mergeable_yet?

      stack.github_api.merge_pull_request(
        stack.github_repo_name,
        number,
        merge_message,
        sha: head.sha,
        commit_message: 'Merged by Shipit',
        merge_method: stack.merge_method
      )
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

**File:** config/routes.rb (L14-14)
```ruby
  resources :webhooks, only: :create
```
