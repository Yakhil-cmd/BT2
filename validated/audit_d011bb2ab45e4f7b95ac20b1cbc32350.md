### Title
Webhook signature verification is bound to the payload's `owner.login`, while all event handlers act on the payload's `repository.full_name` — an authenticated organization can forge webhook events for stacks belonging to a different, unrelated organization ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's GitHub App/webhook secret to verify the HMAC signature against using only `repository.owner.login` (falling back to `organization.login`), while every downstream `Handler` subclass resolves the target `Repository`/`Stack` using the independent `repository.full_name` field, which is never checked for consistency with the field used to select the verifying secret.

### Finding Description
`Shipit::WebhooksController` verifies the `X-Hub-Signature` header against a per-organization webhook secret chosen by: [1](#0-0) 

where `repository_owner` is read straight from the JSON body: [2](#0-1) 

Shipit supports multi-tenant GitHub App configuration keyed by organization (`Shipit.github(organization:)` / `github_app_config`), each with its own `webhook_secret`: [3](#0-2) 

After signature verification succeeds, the raw, unvalidated JSON body is dispatched to handlers: [4](#0-3) 

Every handler resolves the actual `Repository`/`Stack` to act on using `repository.full_name`, a field entirely independent of `repository.owner.login`: [5](#0-4) 

For example, `PushHandler` triggers a real `sync_github` on any stack matching the branch of the resolved repository: [6](#0-5) 

`sync_github` immediately enqueues `GithubSyncJob`, which fetches commits and, if the repository's deploy spec allows it, can lead to caching a new deploy spec / advancing the deployable head: [7](#0-6) [8](#0-7) 

**The break in the trust binding:** the equality the system implicitly assumes is:
`organization whose webhook secret validated the request == organization owning the repository/stack that gets processed`

Nothing enforces this. An attacker who is a legitimate, unprivileged administrator of *their own* onboarded GitHub organization/App in a multi-org Shipit deployment (and therefore knows *their own* org's `webhook_secret`, which they configured) can compute a valid HMAC-SHA1 signature over an arbitrary JSON body containing:
- `repository.owner.login` = their own org (so `verify_signature` picks their own org's app/secret and passes)
- `repository.full_name` = `"victim-org/victim-repo"` (so the handler resolves and acts on a completely different, unrelated `Repository`/`Stack`)

Because `verify_signature` never checks that `repository.full_name` starts with `repository_owner`, or that the resolved `Repository` belongs to the organization that validated the signature, this cross-organization payload passes verification and is processed as if it legitimately originated from GitHub for the victim's repository.

### Impact Explanation
This breaks a repository-to-authenticated-organization binding across tenant boundaries in a single Shipit instance hosting multiple GitHub organizations. A user who only administers Organization A's GitHub App (and thus only knows Organization A's `webhook_secret`) can forge `push`, `status`, `check_suite`, `pull_request`, and `membership` events targeting stacks/repositories belonging to Organization B, without any credentials for Organization B. Concretely for `push`: an attacker can force `GithubSyncJob` to run against a victim stack (`Shipit::GithubSyncJob#perform`), which can advance the stack's known head and trigger `CacheDeploySpecJob`, and for stacks with continuous deployment enabled this can lead to an **unauthorized deploy** being kicked off for a repository the attacker has no legitimate authority over — matching the "Critical: unauthorized deploy" impact bucket. The `status` and `check_suite` handlers can similarly inject forged CI/check state for a victim repository the attacker doesn't own, and the `membership` handler can create teams/users tied to a victim org context.

### Likelihood Explanation
Requires the Shipit instance to be configured for multiple GitHub organizations (the documented "multi github app" configuration schema in `github_app_config`) and requires the attacker to legitimately administer/own the GitHub App for at least one of those organizations (so they know that org's `webhook_secret`) — a realistic scenario for shared/hosted Shipit deployments serving multiple teams/orgs. No access to the victim org, no `ApiClient` token, and no GitHub credentials for the victim are needed; only knowledge of one's own already-configured org's webhook secret and the ability to send an HTTP POST to `/webhooks`.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler`), enforce that the organization used to select the verifying webhook secret matches the organization prefix of `repository.full_name` (and of `organization.login` when present) before dispatching to handlers. Reject the request (422) on mismatch, rather than trusting `repository.full_name` independently of the field used for authentication.

### Proof of Concept
Assume a multi-org Shipit deployment with `github: { org-a: {webhook_secret: SECRET_A, ...}, org-b: {webhook_secret: SECRET_B, ...} }`, and the attacker administers `org-a`'s GitHub App (knows `SECRET_A`), while `org-b/victim-repo` is a real Shipit-managed stack.

1. Attacker builds a push-event JSON body:
```json
{
  "ref": "refs/heads/production",
  "after": "<any sha the attacker wants Shipit to sync toward>",
  "repository": {
    "full_name": "org-b/victim-repo",
    "owner": { "login": "org-a" }
  }
}
```
2. Attacker computes `X-Hub-Signature: sha1=HMAC_SHA1(SECRET_A, body)` — valid, since they legitimately possess `SECRET_A`.
3. POST to `/webhooks` with header `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "org-a")` (from `repository.owner.login`) and verifies successfully against `SECRET_A` [1](#0-0) .
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("org-b/victim-repo")` [5](#0-4)  and calls `stack.sync_github(expected_head_sha: params.after)` for the victim's `production` branch stack [6](#0-5) , triggering `GithubSyncJob` for a repository the attacker does not control, potentially advancing/deploying it.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/stack.rb (L612-614)
```ruby
    def sync_github(expected_head_sha: nil)
      GithubSyncJob.perform_later(stack_id: id, expected_head_sha:)
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
