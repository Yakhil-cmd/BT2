Confirmed: this analog breaks the binding "an organization that authenticated versus the repository that is written" — the webhook signature is verified against a secret keyed by an attacker-supplied organization field, while the resulting action is scoped by a completely separate attacker-supplied repository field that is never covered by that signature.

### Title
Webhook signature verified against attacker-chosen organization while action is scoped to an unrelated repository field - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization secret to validate the HMAC signature against using a field taken directly from the untrusted, unsigned-at-that-point JSON body (`repository.owner.login` / `organization.login`), rather than from any value that is itself authenticated. Meanwhile, the actual side effect performed by the event handlers (e.g. `PushHandler`, `StatusHandler`) is scoped using a different field of the same payload: `repository.full_name`. These two fields are never bound to each other by the signature check.

### Finding Description
`verify_signature` computes:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [1](#0-0) 
where
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

This value is read straight out of the raw request body before the signature has been validated — it is attacker-controlled. It is used only to pick which configured GitHub App's `webhook_secret` to HMAC-check against, via `Shipit.github(organization:)` / `GithubApp#verify_webhook_signature`:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [3](#0-2) 
Note that if the selected organization has no `webhook_secret` configured, verification trivially returns `true` regardless of signature — this is a documented, intentional per-organization configuration option (see `test/dummy/config/secrets_double_github_app.yml`, where `OrgTwo` has `webhook_secret: # nil`) [4](#0-3) .

Once past `verify_signature`, the controller dispatches the full payload to handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [5](#0-4) 
The base `Handler` class resolves which `Stack`/`Repository` to act on using a *different* field of the same body:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [6](#0-5) 

`repository.owner.login` (used for signature key selection) and `repository.full_name` (used for stack resolution/action) are two independent, attacker-editable JSON fields with no cross-validation that they refer to the same repository. This breaks the equality: `organization authenticated == repository written`. Concretely, `PushHandler#process` finds stacks by `repository.full_name`/branch and calls `stack.sync_github(expected_head_sha: params.after)` [7](#0-6) , which enqueues `GithubSyncJob` to fetch and append attacker-influenced commits/state for that stack [8](#0-7) .

### Impact Explanation
An attacker who knows (or can guess) that some configured GitHub organization in `Shipit.github_apps`-style config has no `webhook_secret` set (or has a leaked/weak secret for one org among several configured, as this engine explicitly supports multiple GitHub Apps/orgs — see the multi-org secrets fixture), can craft a webhook POST with:
- `repository.owner.login` / `organization.login` = the weakly-protected/no-secret organization (used only for signature verification), and
- `repository.full_name` = any other tracked repository/stack in the Shipit instance, including ones belonging to organizations with strong secrets.

The signature check passes trivially (`return true unless webhook_secret`), and the handler then acts on the unrelated repository's stack — triggering `GithubSyncJob`, commit ingestion, status creation (`StatusHandler`), or other webhook-driven state changes for a repository the attacker was never authorized to affect. This is a cross-repository write achieved by exploiting an authentication binding that only checks "is this organization's secret valid" without checking "is this the organization whose repository is being mutated."

### Likelihood Explanation
Requires only knowledge of the target Shipit instance being configured with multiple GitHub organizations/Apps where at least one has no `webhook_secret` (an explicitly supported and tested configuration in this codebase) or a weak/exposed secret, plus being able to send an HTTP POST to the public `/webhooks` endpoint — no session, API token, or repository write access is needed. This is a realistic multi-tenant Shipit deployment scenario.

### Recommendation
Bind the field used for signature-key selection to the field used for the actual mutation: verify that `repository.full_name`'s owner matches `repository_owner`/the organization whose secret validated the signature, and reject the webhook otherwise. Alternatively, resolve the target `Stack`/`Repository` strictly from the same organization context used to validate the signature rather than an independent payload field.

### Proof of Concept
1. Configure Shipit with two orgs: `OrgA` (no `webhook_secret`) and `OrgB` (has stacks tracked, strong secret) — matches the pattern already present in `test/dummy/config/secrets_double_github_app.yml`.
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "organization": {"login": "OrgA"},
  "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgB/target-repo"}
}
```
3. `verify_signature` resolves `Shipit.github(organization: "OrgA")`, whose `verify_webhook_signature` returns `true` unconditionally since `OrgA` has no `webhook_secret`.
4. `PushHandler` resolves `Repository.from_github_repo_name("OrgB/target-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")`, mutating `OrgB`'s stack despite the attacker never proving control of `OrgB`'s secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
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
