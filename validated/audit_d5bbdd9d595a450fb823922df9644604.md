### Title
Webhook signature verification keys off `repository.owner.login`, but handlers dispatch writes based on the independent `repository.full_name` field — organization that authenticated ≠ repository that is written - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to validate the HMAC signature against using `repository_owner`, which reads `params.dig('repository', 'owner', 'login')` from the raw JSON body. Every event handler (`Shipit::Webhooks::Handlers::Handler#repository_name`, used by `PushHandler`, `CheckSuiteHandler`, and all `PullRequest::*Handler`s) independently reads `payload.dig('repository', 'full_name')` from the same JSON body to decide which `Repository`/`Stack` records to act on. Because both values are attacker-supplied fields of a single raw HTTP body whose only cryptographic guarantee is "the whole body was HMAC-signed with the secret for the org named in `repository.owner.login`," nothing enforces that `repository.full_name` is consistent with `repository.owner.login`.

### Finding Description
- Verification: `app/controllers/shipit/webhooks_controller.rb`
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
```
`Shipit.github(organization:)` looks up the `GithubApp`/secret for whatever org string is embedded in the attacker-controlled JSON (`repository.owner.login`). `verify_webhook_signature` only checks that `X-Hub-Signature` is a valid HMAC-SHA1 of the raw body under that org's `webhook_secret` (`lib/shipit/github_app.rb`, `verify_webhook_signature`). It never checks that `repository.full_name` is prefixed by that same org.

- Dispatch/write path: `app/models/shipit/webhooks/handlers/handler.rb`
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```
`PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb`) uses `stacks` (resolved from `full_name`) to call `stack.sync_github(expected_head_sha: params.after)`, which enqueues `GithubSyncJob` (`app/jobs/shipit/github_sync_job.rb`) to fetch commits and update the stack. `CheckSuiteHandler` and the `PullRequest::*` handlers similarly resolve their target `Repository`/`Stack`/`PullRequest` from `repository.full_name`, independent from `repository.owner.login`.

**Binding broken (equality that should hold but doesn't):**
`organization_that_authenticated(repository.owner.login) == organization_of(repository.full_name)` is assumed but never enforced — the two fields are read from two different JSON paths of the same attacker-authored body, and only one of them (indirectly, via `Shipit.github(organization: repository_owner)`) is tied to the cryptographic check.

**Attack construction:** An operator of any organization configured in this Shipit deployment (e.g. `secrets.yml`'s `github.SomeOrgTwo.webhook_secret`, per the multi-org config shown in `test/dummy/config/secrets_double_github_app.yml`) knows their own org's `webhook_secret` (they set it themselves in the GitHub App's webhook settings for their own org). They can POST to `/webhooks` a raw JSON body where:
- `repository.owner.login = "OrgTwo"` (so `verify_signature` picks OrgTwo's secret and the attacker's self-computed HMAC over the full raw body validates),
- `repository.full_name = "OrgOne/victim-repo"` (an unrelated org's real repository that is registered as a `Shipit::Repository`).

`verify_signature` passes (correct HMAC for OrgTwo). The dispatched handler then resolves the target `Repository`/`Stack` using `full_name = "OrgOne/victim-repo"`, entirely bypassing any actual authorization from OrgOne.

### Impact Explanation
For `push` events this forces `GithubSyncJob` to run against a victim org's real `Stack`, fetching commits via `stack.github_api` (using the *victim's* correctly-scoped GitHub App credentials, since `stack.github_api` resolves the app for the stack's actual repository) and appending them into the stack's commit history, which can influence deploy-eligible commit lists, CI/status checks correlation, and `continuous_deployment` decision logic on `app/models/shipit/stack.rb`. For `pull_request` events, handlers like `OpenedHandler`/`ClosedHandler` create or archive `review_stacks`/`PullRequest` records against the victim repository (`Shipit::Repository.from_github_repo_name(params.repository.full_name)`), letting the attacker manufacture or archive review-stack state for repositories they don't own. This is a cross-tenant / cross-repository write triggered by an unprivileged party (an admin of an unrelated, lower-trust org configured on the same Shipit instance), matching the Critical "cross-repository writes" / "unauthorized deploy" impact category.

### Likelihood Explanation
Requires only that the Shipit deployment host multiple GitHub organizations (a documented, supported configuration — see `docs/setup.md` and `test/dummy/config/secrets_double_github_app.yml`) and that the attacker controls (knows the webhook secret of) at least one of those orgs, which is normal for any legitimate but lower-trust tenant onboarded onto a shared Shipit instance. No GitHub write access, Shipit session, or `ApiClient` token is required — only the ability to send an HTTP POST to `/webhooks` with a self-signed body.

### Recommendation
In `WebhooksController#verify_signature`/handler dispatch, enforce that the organization used to select the verification secret is the same organization encoded in `repository.full_name` (e.g., require `repository.full_name.split('/').first.casecmp(repository_owner) == 0`, or better, derive `repository_owner` strictly from `full_name` rather than the separate `owner.login` sub-object) before invoking any handler that resolves `Repository`/`Stack` records.

### Proof of Concept
1. Configure Shipit (per `docs/setup.md`) with two GitHub Apps: `OrgOne` (victim, owns `Shipit::Repository` `"OrgOne/victim-repo"` with active stacks) and `OrgTwo` (attacker-controlled tenant, `webhook_secret = "orgtwo-secret"`).
2. Attacker builds payload:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef...",
  "repository": {
    "owner": { "login": "OrgTwo" },
    "full_name": "OrgOne/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(orgtwo-secret, raw_body)>` and sends:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=<computed>
<raw_body above>
```
4. `verify_signature` resolves `repository_owner => "OrgTwo"`, fetches OrgTwo's `webhook_secret`, and successfully verifies the attacker's own signature.
5. `Shipit::Webhooks::Handlers::PushHandler.call` runs with `repository_name = "OrgOne/victim-repo"`, resolving OrgOne's real stacks and enqueuing `GithubSyncJob` against them — a write to a repository/org the attacker never authenticated as. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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
