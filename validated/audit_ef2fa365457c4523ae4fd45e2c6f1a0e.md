I found a concrete cross-organization binding break in the webhook signature verification path that mirrors the Eggs Finance bug class: a value that gates a privileged action (which stack/repo gets written to) is never covered by the check that is supposed to authorize the action.

### Title
Webhook signature verification key is derived from `repository.owner.login`, but processing acts on `repository.full_name` — cross-organization stack sync forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub organization's `webhook_secret` to use for HMAC verification based on `repository.owner.login` (or `organization.login`), [1](#0-0) [2](#0-1) . However, once the signature passes, the actual stack/repository that gets mutated is resolved from a *different* field of the same payload, `repository.full_name`, via `Repository.from_github_repo_name`, which is a plain DB lookup with no cross-check against the organization that was used to authorize the request [3](#0-2) [4](#0-3) .

### Finding Description
In a multi-organization Shipit deployment, each GitHub organization has its own `webhook_secret` configured under `secrets.github[org]` [5](#0-4) . `Shipit.github(organization:)` looks up the app/secret for a specific org name [6](#0-5) .

The controller picks *which* organization's secret to verify against using:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

This value is attacker-controlled JSON in the raw request body — it is read *before* the signature has been verified, purely to decide which secret to check the signature against [1](#0-0) .

Once `verify_signature` passes, `create` dispatches the full JSON payload to handlers [7](#0-6) . Handlers such as `PushHandler` resolve the target `Repository`/`Stack` using `repository.full_name` instead of `repository.owner.login`:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end

def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end
``` [3](#0-2) 

`Repository.from_github_repo_name` simply splits `"owner/name"` and does a `find_by`, with no relation to which organization secret authenticated the request [4](#0-3) .

This breaks the intended binding: **`organization authenticated (repository.owner.login)` == `organization/repository written (repository.full_name)`**. An attacker who administers their own GitHub organization/App installation on Shipit (and therefore legitimately knows their own org's `webhook_secret`) can send `repository.owner.login = "attacker-org"` (to pass signature verification with their own known secret) while setting `repository.full_name = "victim-org/victim-repo"` (a Stack belonging to a different, victim organization that is also configured on the same Shipit instance). Since the signature only proves "this HMAC matches attacker-org's secret over this exact byte string", and nothing re-validates that `repository.full_name`'s owner matches `repository.owner.login`, the forged payload is accepted and dispatched to handlers that act on the victim's Stack — e.g. `PushHandler` will call `stack.sync_github(expected_head_sha: ...)` for the victim's stack [8](#0-7) , enqueuing `GithubSyncJob` which fetches commits using the stack's own configured `github_api` and writes them into the stack's commit history [9](#0-8) .

### Impact Explanation
This crosses a genuine organizational trust boundary in a multi-org Shipit deployment: an attacker who is a legitimate, unprivileged administrator of *their own* GitHub org (and thus knows only their own webhook secret) can forge webhook deliveries that are accepted as authentic for a *different* organization's repositories/stacks, triggering unauthorized stack synchronization (and, depending on which handler fires, other repository-scoped side effects such as `status` updates, `check_suite` refreshes, or PR/review-stack provisioning) on a stack they do not own or control. This is a cross-repository/cross-organization write achieved purely by exploiting the mismatch between the field used for authentication and the field used for authorization of the write target.

### Likelihood Explanation
This requires a Shipit instance configured with **multiple GitHub organizations** (the multi-org config schema shown in `secrets.development.example.yml` and handled by `github_app_config`) [5](#0-4) , and requires the attacker to control at least one organization/App installation registered on that instance — a realistic scenario for shared/hosted Shipit deployments serving multiple orgs. No privileged Shipit credentials, session, or `ApiClient` token are needed; only a legitimately-issued `webhook_secret` for the attacker's own (unprivileged, from Shipit's perspective) organization.

### Recommendation
After signature verification, re-derive the organization/owner strictly from the same field that determined the signing secret (`repository.owner.login` / `organization.login`), and reject or ignore any event where `repository.full_name`'s owner segment does not match the organization whose secret validated the signature. Do not allow `repository.full_name` (used for `Repository.from_github_repo_name`) to reference an owner different from the one that authorized the webhook.

### Proof of Concept
1. Shipit is configured with two organizations, `attacker-org` (secret `S_attacker`, known to the attacker) and `victim-org` (secret `S_victim`, unknown to the attacker), each with an app/repo registered as a Shipit `Repository`/`Stack`.
2. Attacker builds a JSON payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(S_attacker, raw_body)>` using their own known secret and POSTs directly to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and validates successfully against `S_attacker` [1](#0-0) .
5. `create` dispatches the payload to `PushHandler`, which resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and enqueues sync work against the victim's stack [8](#0-7) , even though the request was never authorized by `victim-org`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** lib/shipit.rb (L170-181)
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
```

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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
