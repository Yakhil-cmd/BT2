This confirms the exploit chain end-to-end. `Handlers::StatusHandler#process` at `app/models/shipit/webhooks/handlers/status_handler.rb:20-24` matches purely on `Commit.where(sha: params.sha)` with **no repository/organization scoping whatsoever** — unlike `PushHandler` or `CheckSuiteHandler` which scope via `stacks`. And `add_status`/`create_status_from_github!` (`app/models/shipit/commit.rb:366-384`) directly drives `stack.schedule_merges` and feeds `Commit#deployable?` (`app/models/shipit/commit.rb:227-229`), which gates `Stack#next_commit_to_deploy` / `ProcessMergeRequestsJob#perform` (`app/jobs/shipit/process_merge_requests_job.rb:10-31`) merges and continuous-delivery deploys.

The multi-org feature is explicitly documented (`docs/setup.md:182-209`, `config/secrets.development.example.yml:18-38`) and exercised in fixtures (`test/dummy/config/secrets_double_github_app.yml`), each org independently keyed with its own optional `webhook_secret`. `WebhooksController#verify_signature`/`#repository_owner` (`app/controllers/shipit/webhooks_controller.rb:24-61`) picks the org's `GitHubApp` purely from `repository.owner.login` in the unsigned JSON body, and `GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`) trivially returns `true` when that org's `webhook_secret` is blank.

### Title
Cross-repository forged CI status via webhook org/repository binding mismatch enables unauthorized merges/deploys - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
In a multi-GitHub-org Shipit deployment, `WebhooksController#verify_signature` selects which organization's webhook secret to check based solely on the attacker-supplied `repository.owner.login` (or `organization.login`) field of the unsigned JSON body. `StatusHandler#process` then applies the status update by matching on `commit.sha` alone, globally across every stack/repository tracked by the entire Shipit instance, with no verification that the commit actually belongs to the organization whose secret authenticated the request.

### Finding Description
`repository_owner` (`app/controllers/shipit/webhooks_controller.rb:59-62`) reads `params.dig('repository','owner','login')` to pick `Shipit.github(organization: repository_owner)` and validate `X-Hub-Signature` against that organization's secret (`lib/shipit/github_app.rb:76-83`). If that organization has no `webhook_secret` configured (an explicitly supported, documented configuration — `docs/setup.md:182-209`, sample configs ship with `webhook_secret: # nil` for every org, `config/secrets.development.example.yml:18-38`, `test/dummy/config/secrets_double_github_app.yml`), `verify_webhook_signature` returns `true` unconditionally, so *any* unauthenticated caller can produce a "verified" webhook for that org's identity.

Once verified, `WebhooksController#create` dispatches to `Handlers::StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`):
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
Unlike `PushHandler`/`CheckSuiteHandler`, which scope through `stacks` (derived from `repository.full_name`), `StatusHandler` performs **no repository scoping at all** — it matches any commit in the database by SHA, regardless of which stack/repository/organization it belongs to. The binding broken is: the organization that authenticated the webhook (`repository.owner.login`, resolved to a possibly-secret-less org) ≠ the repository/commit that is actually written (any commit, in any org's stack, matched purely by SHA).

### Impact Explanation
By crafting a payload with `repository.owner.login` set to any organization configured in the Shipit instance without a webhook secret, and `sha` set to a known commit SHA belonging to a *different*, properly-secured organization's stack, an unauthenticated attacker can inject arbitrary fake commit statuses (e.g., state: `success`) for that commit. This:
- Makes `Commit#deployable?` (`app/models/shipit/commit.rb:227-229`) return true regardless of real CI outcome, bypassing `ci.require`/`ci.blocking` protections.
- Triggers `stack.schedule_merges` (`app/models/shipit/commit.rb:383`) → `ProcessMergeRequestsJob` (`app/jobs/shipit/process_merge_requests_job.rb:10-31`), which can auto-merge pull requests once `all_status_checks_passed?`.
- Feeds `Stack#trigger_continuous_delivery`/`next_commit_to_deploy` (`app/models/shipit/stack.rb:210-243`), enabling an unauthorized deploy of a commit that never actually passed CI, on a repository entirely unrelated to the organization whose (absent) secret was used to authenticate the request.

This constitutes an unauthorized deploy/merge through an authentication-boundary mismatch, matching the Critical impact bar (unauthorized deploy/rollback/merge).

### Likelihood Explanation
Requires: (1) the target Shipit instance to use the documented multi-organization GitHub App configuration (a first-class, supported feature, not a misconfiguration outside the docs) with at least one organization lacking a `webhook_secret`, and (2) attacker knowledge of a target commit SHA (trivially obtainable for any commit pushed to a tracked repo, public or via any existing webhook traffic/log). No credentials, session, or API token are required — only an HTTP POST to the public `/webhooks` endpoint.

### Recommendation
`StatusHandler` (and any other handler that doesn't scope by `stacks`) must verify that the commit being updated actually belongs to a stack whose repository matches `repository.full_name` from the payload, and that repository's owner must match the `repository_owner` used for signature verification. More generally, `WebhooksController#verify_signature` should ensure the organization used to select the webhook secret is intrinsically tied to the repository whose data will be mutated, not just used to pick a signature-check secret independently of the write path.

### Proof of Concept
1. Configure Shipit with two GitHub orgs, `weak-org` (no `webhook_secret`) and `secure-org` (real `webhook_secret`), each with tracked stacks (as documented in `docs/setup.md:182-209`).
2. Identify a commit SHA belonging to a `secure-org` stack tracked by Shipit (e.g., from the stack's commit list, publicly visible on GitHub).
3. Send, without any authentication:
```
POST /webhooks
X-Github-Event: status

{
  "sha": "<secure-org-commit-sha>",
  "state": "success",
  "context": "ci/circleci",
  "repository": { "owner": { "login": "weak-org" } }
}
```
4. `verify_signature` resolves `Shipit.github(organization: "weak-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` with no `X-Hub-Signature` header needed.
5. `StatusHandler#process` matches `Commit.where(sha: "<secure-org-commit-sha>")` and calls `create_status_from_github!`, marking the `secure-org` commit as `success`, potentially triggering an unauthorized merge or deploy. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-27)
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
      end
    end
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```

**File:** app/jobs/shipit/process_merge_requests_job.rb (L1-34)
```ruby
# frozen_string_literal: true

module Shipit
  class ProcessMergeRequestsJob < BackgroundJob
    include BackgroundJob::Unique
    on_duplicate :drop

    queue_as :default

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
    end
  end
end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```
