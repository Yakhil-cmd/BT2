### Title
Webhook signature verified against the wrong organization's secret, letting an attacker's own GitHub org spoof push events for a victim repository - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization secret to check the `X-Hub-Signature` against using `repository_owner`, taken from `payload.dig('repository', 'owner', 'login')` (falling back to `payload.dig('organization', 'login')`). The actual repository that the webhook payload is applied to is instead derived independently by `Webhooks::Handlers::Handler#repository_name`, which reads `payload.dig('repository', 'full_name')`. Because these are two different, attacker-controlled fields of the same unsigned JSON body, the field that is cryptographically checked (`repository.owner.login`) is not the field that is acted upon (`repository.full_name`).

### Finding Description
The signature check binds the verification to whichever organization's secret is selected by `repository_owner`: [1](#0-0) [2](#0-1) 

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

Once verification passes, the event handler resolves the target repository/stack from a **different** JSON field, `repository.full_name`, not `repository.owner.login`: [3](#0-2) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`PushHandler#process` then acts on every matching stack for the branch, calling `stack.sync_github(expected_head_sha: params.after)`: [4](#0-3) 

This breaks the equality the signature check is meant to enforce: `organization verified == organization written`. An attacker who legitimately controls their own organization/repo already registered in the Shipit instance (and therefore knows/possesses a valid webhook secret for that org, since Shipit generates/stores a secret per GitHub App/organization installation) can craft a raw JSON payload where:
- `repository.owner.login` = the attacker's own organization (so `Shipit.github(organization: repository_owner)` picks the attacker's own webhook secret, and the HMAC computed with that secret over the raw body validates), and
- `repository.full_name` = `"victim-org/victim-repo"` (an unrelated stack already configured on the same Shipit instance).

The request passes `verify_signature` because the org used for the crypto check is the attacker's, then `PushHandler` (or `StatusHandler`/`CheckSuiteHandler`, which use the same `Handler#repository_name` helper) resolves and mutates state for the victim's `Stack` via `Repository.from_github_repo_name("victim-org/victim-repo")`, enqueuing `GithubSyncJob` against the victim stack: [5](#0-4) 

This is exactly the analog class called out in scope: "an organization that authenticated versus the repository that is written."

### Impact Explanation
The forged push causes `GithubSyncJob` to run against the victim's stack, fetching commits from GitHub using Shipit's own credentials (`stack.github_api`) and creating `Commit` records via `append_commit`, then triggering `CacheDeploySpecJob`. On stacks with continuous deployment enabled, this state mutation on a stack the attacker does not control feeds directly into automatic deploy triggers, constituting an unauthorized cross-repository write/trigger achieved purely by controlling their own separate organization's webhook secret — no privileged access to the victim organization is required. This qualifies as Critical (cross-repository writes / unauthorized deploy).

### Likelihood Explanation
The precondition is realistic and low-privilege: the attacker only needs their *own* organization/repository already onboarded to the same Shipit instance (a normal, unprivileged use case for any org that self-hosts or shares a Shipit deployment across teams), giving them a legitimately-issued webhook secret for their own org. They then send a single crafted HTTP request to the shared `WebhooksController` endpoint with mismatched `repository.owner.login` vs `repository.full_name` fields. No secrets belonging to the victim are needed.

### Recommendation
Verify the webhook signature using the secret associated with the same repository/organization that will actually be acted upon. Concretely, derive both the signing organization and the acted-upon repository from the *same* field (e.g., always use `repository.full_name`'s owner segment, or cross-check that `repository.owner.login` and `repository.full_name`'s owner match before dispatching), and reject the request if they diverge. Consider signing on a per-repository/stack secret rather than a per-organization one, so that a payload naming repo A can never be validated with repo B's secret.

### Proof of Concept
```
POST /webhooks HTTP/1.1
X-Github-Event: push
X-Hub-Signature: sha1=<hmac(attacker_org_secret, raw_body)>
Content-Type: application/json

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
`verify_signature` looks up `Shipit.github(organization: "attacker-org")` and validates the HMAC using the attacker's own known secret — passes. `PushHandler#stacks` then resolves stacks for `"victim-org/victim-repo"` and calls `sync_github(expected_head_sha: "<attacker-chosen sha>")` on the victim's stack, exactly as if GitHub itself had sent this event for the victim repository. [6](#0-5) [7](#0-6)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
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
```

**File:** app/jobs/shipit/github_sync_job.rb (L18-41)
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
```
