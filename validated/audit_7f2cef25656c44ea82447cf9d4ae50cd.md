### Title
Cross-repository commit status forgery via unscoped `StatusHandler` webhook processing - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates an incoming webhook against the GitHub organization/App derived from the payload's `repository.owner.login` (or `organization.login`), proving only that *some* org/repo owned by that GitHub App sent the request. [1](#0-0)  However, `StatusHandler#process` never re-checks which repository the event actually belongs to — it updates commit statuses globally by SHA across the entire Shipit database, breaking the binding between "organization/repository authenticated by the signature check" and "the repository whose commit is actually written."

### Finding Description
The signature check picks the GitHub App/secret to validate against using only the repository owner parsed from the payload: [2](#0-1) 

Most event handlers correctly scope database writes to the repository that emitted the webhook, using `Repository.from_github_repo_name(repository_name)`-derived `stacks`: [3](#0-2) 

`CheckSuiteHandler`, for example, correctly scopes commit lookups through `stacks`: [4](#0-3) 

But `StatusHandler` does not require a `:repository` field at all and queries `Commit` globally by SHA, with no repository/stack scoping whatsoever: [5](#0-4) 

Because git commit SHAs are content-addressed, an attacker who controls their own onboarded GitHub organization/repository (legitimately installed on the same multi-tenant Shipit instance) can reproduce a commit with an *identical* SHA to one that exists in a victim's tracked repository — e.g. by pushing an identical tree/commit (same parent, author, committer, timestamps, message) from a public target repo into their own repo, or via a fork/mirror that shares history. The attacker then sets an arbitrary commit status (state `success`, matching context) on that commit via the GitHub API for their own repository. GitHub signs and delivers the `status` webhook using the attacker's own organization's webhook secret, which passes `verify_signature` because the check only validates "this org's secret matches," not "this org owns the commit being written."

`StatusHandler#process` then matches `Commit.where(sha: params.sha)` against **every** stack in the installation, and writes the forged status onto the victim's commit: [6](#0-5) 

### Impact Explanation
A forged `success` status with a context matching the victim stack's `required_statuses` (configured in that stack's `shipit.yml`) can satisfy CI gating for `deployable?`: [7](#0-6) [8](#0-7) 

If the victim stack has `continuous_deployment` enabled or a human trusts the (forged) green status, this can cause an **unauthorized deploy** of a commit that never actually passed the victim's real CI/checks. It also lets an unrelated tenant pollute another tenant's commit status history/UI, an integrity violation across a repository/organization trust boundary that the signature-verification step was supposed to enforce.

### Likelihood Explanation
The attacker needs only their own onboarded org/repo (a standard SaaS-tenant capability, not privileged access to the victim), and the ability to reproduce a commit with an identical SHA to a target commit (trivial for public/mirrored/forked repos, or any content-identical commit). No victim credentials, webhook secret, API token, or session are required — only the normal GitHub status-webhook flow for a repository the attacker legitimately controls.

### Recommendation
Scope `StatusHandler#process` to the repository/stack derived from the webhook payload, mirroring `CheckSuiteHandler`/`PushHandler`: require and parse `params.repository.full_name`, resolve `stacks` via `Repository.from_github_repo_name`, and restrict the `Commit` lookup to `stack.commits.where(sha: params.sha)` instead of a global `Commit.where(sha:)`.

### Proof of Concept
1. Attacker onboards `attacker-org/attacker-repo` on the shared Shipit instance (legitimate GitHub App installation).
2. Attacker identifies a commit SHA `S` present in `victim-org/victim-repo` (public repo, or shared fork/mirror history) that is tracked as a Shipit stack.
3. Attacker reproduces an identical commit (same tree, parents, author/committer identities and timestamps, message) inside `attacker-org/attacker-repo`, yielding the same SHA `S`.
4. Attacker calls the GitHub Statuses API on `attacker-org/attacker-repo` for commit `S` with `state: success`, `context: <required-context-for-victim-stack>`.
5. GitHub sends a `status` webhook signed with `attacker-org`'s webhook secret; `WebhooksController#verify_signature` validates it successfully because it only checks the org's own secret.
6. `StatusHandler#process` runs `Commit.where(sha: S)`, which also matches the commit in `victim-org/victim-repo`, and calls `create_status_from_github!` on it — writing a forged `success` status onto the victim's commit, potentially satisfying `required_statuses` and enabling an unauthorized deploy.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L1-21)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class CheckSuiteHandler < Handler
        params do
          requires :check_suite do
            requires :head_sha, String
            requires :head_branch, String
          end
        end
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
      end
    end
  end
end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-28)
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
end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/deploy_spec.rb (L194-196)
```ruby
    def required_statuses
      (Array.wrap(config('ci', 'require')) + blocking_statuses).uniq
    end
```
