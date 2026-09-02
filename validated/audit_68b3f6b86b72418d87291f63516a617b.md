### Title
Cross-repository CI status forgery via unscoped `sha`-only lookup in `StatusHandler` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits purely by `sha` across the entire installation, without checking that the `repository` field of the (signature-verified) webhook payload actually matches the repository owning the commit it mutates. This breaks the same trust binding described in GHSA-2026-011: the signature/HMAC authenticates "this GitHub organization sent this payload", but the code then acts on a scope (any commit sharing that SHA, in any repo/stack) that was never covered by that authentication decision.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to verify against using `repository_owner`, derived from the payload's `repository.owner.login` (or `organization.login`), and validates the HMAC over the full raw body. [1](#0-0) 

This proves only that *the organization identified in the payload* actually sent this payload — i.e. the binding is `authenticated_org == payload.repository.owner`. Once verified, `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`: [2](#0-1) 

`StatusHandler` only requires `sha` and `state` from the payload, and never consults `repository`/`payload.dig('repository', 'full_name')` at all: [3](#0-2) 

It then mutates *every* `Commit` in the database whose `sha` matches, regardless of which stack/repository that commit belongs to:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
Contrast this with `PushHandler`, which correctly scopes its action to the repository named in the (signed) payload via the shared `Handler#stacks` helper (`Repository.from_github_repo_name(repository_name)`): [4](#0-3) [5](#0-4) 

So the equality that should hold — `organization that authenticated the webhook == repository whose commit status is written` — is enforced for `push` events but dropped for `status` events. Any organization onboarded to this Shipit instance (each with its own configured `webhook_secret`/GitHub App per `config/secrets.yml`, see `docs/setup.md` multi-org section) can send a validly-signed `status` event for its own repository containing an arbitrary `sha`/`state`/`context` combination. If that `sha` also identifies a commit tracked under a *different* organization's stack (e.g. identical commits from a shared upstream/fork, a monorepo split into multiple Shipit-tracked repos, or a cherry-picked/rebased commit whose SHA is reused), the handler will happily attach a forged CI status to that unrelated commit.

### Impact Explanation
`Commit#create_status_from_github!` feeds `Shipit::CommitChecks`/`Status::Group`, which stacks use to decide whether a commit is "deployable" (CI green) and safe to merge/deploy. [6](#0-5) 
An attacker who controls (or merely authenticates as) one organization onboarded onto the shared Shipit instance can forge a `success` status for a commit belonging to a stack under a different, unrelated organization, potentially causing that commit to appear deployable/mergeable when its real CI has not passed — an unauthorized-deploy-class impact under the stated High/Critical bar (unauthorized deploy/merge decision made on forged CI state).

### Likelihood Explanation
This requires the attacker to control (or have push access to) a repository/organization that is itself legitimately configured in the Shipit instance's `github` secrets (multi-org deployments are an explicitly documented, supported configuration in `docs/setup.md`). It further requires a SHA collision/reuse across repositories, which is realistic in monorepo-splits, forks, or cherry-pick/rebase workflows but not universal. This is a real, unmitigated architectural gap in `StatusHandler` rather than a purely theoretical concern, but the practical blast radius depends on the deployment topology (single-org installs are unaffected since there is only one org to spoof from).

### Recommendation
Scope `StatusHandler#process` to the repository asserted in the verified payload, mirroring `PushHandler`/`Handler#stacks`: only update `Commit` records belonging to stacks whose `Repository` matches `payload.dig('repository', 'full_name')` (or `organization.login`), rejecting/ignoring status updates for shas that don't belong to that repository's known commits.

### Proof of Concept
1. Shipit is configured for two GitHub organizations, `org-a` and `org-b`, each with its own `webhook_secret` per the multi-org config in `docs/setup.md`.
2. `org-a` (attacker-controlled) has a commit whose SHA happens to equal a commit SHA tracked in `org-b`'s stack (e.g., both forked from the same public upstream commit, or a cherry-pick preserving the original SHA context in a monorepo split).
3. Attacker sends `POST /webhooks` with `X-Github-Event: status`, a body `{"sha": "<shared_sha>", "state": "success", "repository": {"owner": {"login": "org-a"}, "full_name": "org-a/foo"}, ...}`, correctly signed with `org-a`'s `webhook_secret` (which the attacker/org-a legitimately possesses).
4. `verify_signature` passes because the signature is valid for `org-a`.
5. `StatusHandler#process` executes `Commit.where(sha: "<shared_sha>")`, which also matches the commit in `org-b`'s stack, and calls `create_status_from_github!` on it — writing a forged "success" CI status onto a commit that `org-a` never authenticated to touch.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-25)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/commit_checks.rb (L1-4)
```ruby
# frozen_string_literal: true

module Shipit
  class CommitChecks < EphemeralCommitChecks
```
