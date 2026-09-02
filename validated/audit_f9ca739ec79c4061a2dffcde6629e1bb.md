Confirmed: `StatusHandler.process` at `app/models/shipit/webhooks/handlers/status_handler.rb:20-24` does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — a global lookup by `sha` across **all** stacks/repositories, with zero binding to `repository.full_name` at all (unlike `PushHandler`, which at least scopes through `stacks`/`Repository.from_github_repo_name`). Combined with `WebhooksController#verify_signature`'s org-selection logic based on `repository_owner` (falling back to `organization.login`), this confirms the exploit path.

### Title
Webhook signature is verified against an attacker-chosen organization while the write target (commit/repository) is taken from unrelated, unverified payload fields - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and therefore which `webhook_secret`) to validate the incoming request against by reading `repository_owner`, which is computed as `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) . Nothing ties this "authenticating organization" to the repository/commit that the resulting webhook handler actually mutates: handlers resolve their target purely from `payload.dig('repository','full_name')` [2](#0-1)  or, in the case of `StatusHandler`, from a bare `sha` lookup across the entire `Commit` table with no repository scoping at all [3](#0-2) .

### Finding Description
Shipit supports hosting multiple GitHub organizations behind one instance, each with its own `webhook_secret`, as documented and fixture-demonstrated [4](#0-3) [5](#0-4) . `GitHubApp#verify_webhook_signature` explicitly *skips* signature validation entirely when an organization has no `webhook_secret` configured:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [6](#0-5) 

The organization used to pick which `GitHubApp`/secret applies is derived entirely from attacker-controlled JSON body fields, not from anything cryptographically verified beforehand:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

Because `repository.owner.login` is optional and simply falls back to `organization.login` when absent, an attacker can craft a raw POST to `/webhooks` that:
1. Sets `organization.login` to any org configured with a blank/unset `webhook_secret` (a state the docs and example configs treat as normal/valid), causing `verify_signature` to pass unconditionally regardless of the `X-Hub-Signature` header.
2. Omits `repository.owner.login`, but sets `repository.full_name` (or, for `status` events, just `sha`) to point at a completely different, fully-protected repository/stack tracked by Shipit.

The handler that processes the event never re-checks that the "authenticated" organization matches the organization owning the targeted repository/commit — `PushHandler`, `StatusHandler`, and the various `pull_request` handlers all resolve their target purely from `repository.full_name` or `sha` [7](#0-6) [3](#0-2) . This breaks the equality that should hold: *organization that authenticated the request* == *organization owning the repository being written*.

`StatusHandler` is the most severe case: it looks up `Commit.where(sha: params.sha)` with **no repository/organization filter whatsoever**, so any commit sha tracked anywhere in the Shipit instance can have a forged CI status (e.g. `state: "success"`) injected via `commit.create_status_from_github!(params)` [8](#0-7) .

A forged "success" status feeds directly into deploy and merge-queue gating logic:
- `Commit#deployable?` depends on `success?` from the injected status [9](#0-8) , and `add_status` schedules `ProcessMergeRequestsJob` whenever a commit becomes `pending` or `success` [10](#0-9) .
- `MergeRequest::StatusChecker` / `all_status_checks_passed?` / `any_status_checks_failed?` rely on exactly these replicated statuses to decide `reject_unless_mergeable!` and `merge!` [11](#0-10) , and `ProcessMergeRequestsJob` will call `merge_request.merge!` once `all_status_checks_passed?` is true [12](#0-11) .

So a forged status webhook — authenticated only against an unrelated, secret-less organization — can cause an unrelated stack's pull request to pass CI gating and be automatically merged/deployed.

### Impact Explanation
This is a cross-organization/cross-repository trust-boundary break: authentication is bound to one organization (the attacker's choice of a misconfigured/secret-less org) while the write lands on a different, fully-protected repository's commits and merge queue. The consequence — bypassing CI gating to trigger an automatic merge via `MergeRequest#merge!` (which pushes to GitHub with the app's credentials) — falls under "unauthorized ... merge", explicitly listed as Critical impact. It can also cause `ProcessMergeRequestsJob`/`sync_github` (via forged `push` events) to act on stacks the attacker has no legitimate relationship to.

### Likelihood Explanation
Exploitation requires only network access to the Shipit instance's `/webhooks` endpoint (no session, no `ApiClient` token, no knowledge of any org's real `webhook_secret`) plus the deployment being configured for multiple GitHub organizations where at least one has no `webhook_secret` set — a state explicitly presented as a normal/supported configuration in the project's own docs and example secrets files [4](#0-3) [13](#0-12) .

### Recommendation
- Do not allow `verify_webhook_signature` to return `true` when `webhook_secret` is blank; treat a missing secret as "reject all webhooks for this organization" instead of "accept all."
- After signature verification, re-derive the organization from the verified `repository.full_name`/`organization.login` used by the handler and assert it matches the organization whose secret validated the signature.
- In `StatusHandler` (and any other handler doing a bare `Commit`/global lookup), scope the query by the repository resolved from the verified payload instead of `sha` alone.

### Proof of Concept
Assume a multi-org Shipit deployment where `OrgB` is configured without a `webhook_secret` (per the documented multi-org config), and `OrgA/protected-repo` is a tracked stack with an open pull request awaiting real CI:

```
POST /webhooks HTTP/1.1
X-Github-Event: status
X-Hub-Signature: sha1=anything-or-omitted

{
  "organization": { "login": "OrgB" },
  "sha": "<head-sha-of-OrgA-protected-repo-PR>",
  "state": "success",
  "context": "ci/required-check"
}
```
`repository_owner` resolves to `OrgB` (no `repository` key present) → `Shipit.github(organization: 'OrgB').verify_webhook_signature` returns `true` unconditionally (`webhook_secret` blank) → `StatusHandler.process` runs `Commit.where(sha: ...)`, matching the commit inside `OrgA/protected-repo`, and records a forged `success` status → `ProcessMergeRequestsJob` subsequently merges the pull request via `stack.github_api.merge_pull_request`, all without the attacker ever holding credentials for `OrgA` or Shipit itself.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```

**File:** app/models/shipit/merge_request.rb (L155-206)
```ruby
    def reject_unless_mergeable!
      return reject!('merge_conflict') if merge_conflict?
      return reject!('ci_missing') if any_status_checks_missing?
      return reject!('ci_failing') if any_status_checks_failed?
      return reject!('requires_rebase') if stale?

      false
    end

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
      begin
        if stack.github_api.pull_requests(stack.github_repo_name, base: branch).empty?
          stack.github_api.delete_branch(stack.github_repo_name, branch)
        end
      rescue Octokit::UnprocessableEntity
        # branch was already deleted somehow
      end
      complete!
      true
    rescue Octokit::MethodNotAllowed # merge conflict
      reject!('merge_conflict')
      false
    rescue Octokit::Conflict # shas didn't match, PR was updated.
      raise NotReady
    end

    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```

**File:** app/jobs/shipit/process_merge_requests_job.rb (L21-30)
```ruby
      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
        rescue MergeRequest::NotReady
          ProcessMergeRequestsJob.set(wait: 10.seconds).perform_later(stack)
          return false
        end
```

**File:** config/secrets.development.example.yml (L1-17)
```yaml
host: 'localhost:3000'
redis_url: 'redis://127.0.0.1:6379/0'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app
# Can be obtained there: https://github.com/settings/apps
# Set the "Authorization callback URL" as `<host>/github/auth/github/callback`

github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional

```
