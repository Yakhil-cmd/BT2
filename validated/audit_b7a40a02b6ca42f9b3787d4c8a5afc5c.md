### Title
Webhook organization used for signature verification is decoupled from the repository the payload acts on, allowing cross-organization webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
The Celo report is about a mutex-less, dual-writer/reader binding that lets two independently-derived pieces of shared state diverge. The same *bug class*—two values that should be bound together but are derived and validated independently—appears in Shipit's webhook trust boundary: the organization used to pick the HMAC secret for signature verification is not the same field used to determine which repository/stack the webhook payload is applied to.

### Finding Description
`WebhooksController#verify_signature` selects which `GitHub App`/secret to validate against using `repository_owner`, itself pulled from the payload: [1](#0-0) [2](#0-1) 

Verification itself is delegated to `GitHubApp#verify_webhook_signature`, which explicitly **skips verification entirely** when no `webhook_secret` is configured for that organization (webhook secret is documented as optional per-organization setup): [3](#0-2) 

Once the request passes (or is exempted from) this check, the actual webhook handlers determine *which repository/stack to act on* using a **different** field of the same payload — `repository.full_name` — with no cross-check against the `repository.owner.login`/`organization.login` field used above: [4](#0-3) [5](#0-4) 

Nothing enforces that `repository.owner.login` (the identity that authenticated the request) equals the owner segment of `repository.full_name` (the identity whose stacks are written to). For a legitimate GitHub-originated webhook, GitHub guarantees this consistency, but Shipit's own verification logic does not, and the payload is fully attacker-constructed for this endpoint (`WebhooksController#create` parses raw JSON with no other authentication): [6](#0-5) 

Concretely: in a multi-organization Shipit deployment, if **any one** configured organization has no `webhook_secret` set (an explicitly supported, optional configuration), `verify_webhook_signature` returns `true` unconditionally for payloads claiming that organization as `repository.owner.login`/`organization.login` — with zero credential requirement. An attacker can then set `repository.full_name` (and other identifying fields) inside the same forged payload to point at a completely different, fully-secured victim organization's repository/stack. `PushHandler` will resolve `stacks` via `Repository.from_github_repo_name(repository_name)` using that spoofed `full_name`, and enqueue `stack.sync_github(...)` for the victim stack: [7](#0-6) 

This mirrors the report's core flaw: two related values (the authenticating identity and the identity that is acted upon) are trusted to stay consistent without any synchronization/enforcement, allowing one to diverge from the other under attacker control.

### Impact Explanation
`GithubSyncJob`, triggered via the spoofed push webhook, fetches and appends real, already-existing commits into the victim stack's commit history and can trigger a spec-cache/CI recompute: [8](#0-7) 

If the victim stack has `continuous_deployment` enabled, newly-synced commits become eligible for the next scheduled `ContinuousDeliveryJob`, meaning an unprivileged, unauthenticated attacker can force an out-of-band resync/deploy trigger on a stack they have no access to, purely by knowing that some *other*, unrelated organization in the same Shipit instance omitted its webhook secret. This crosses the "unauthorized deploy" impact bucket without needing a Shipit session, API token, or the victim organization's webhook secret — only the (documented-as-optional) absence of a secret on any one tenant.

### Likelihood Explanation
Requires: (1) a multi-tenant Shipit deployment serving more than one GitHub organization, and (2) at least one configured organization without a `webhook_secret` (explicitly called out as "optional" in the setup docs). Given webhook secret is optional per org, this is a plausible real-world misconfiguration, and no other credential or session is needed to exploit it once present — only network access to the `/webhooks` endpoint.

### Recommendation
- Require `webhook_secret` to be mandatory for every configured organization, or reject requests entirely (rather than short-circuiting to `true`) when a secret is absent.
- Validate that `repository.owner.login`/`organization.login` (the identity used to select/verify the signature) matches the owner segment of `repository.full_name` (or the `repository`/`organization` field actually used by handlers) before dispatching to `Shipit::Webhooks.for_event(event)`.
- Consider verifying the signature using the secret associated with the resolved repository/stack rather than an attacker-supplied owner field.

### Proof of Concept
1. Configure Shipit with two organizations: `org-a` (no `webhook_secret` set) and `org-b/victim-repo` (real, secured stack, `continuous_deployment: true`).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<a real commit sha that exists on org-b/victim-repo>",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  }
}
```
No `X-Hub-Signature` needed (or any arbitrary value), since `org-a` has no `webhook_secret`, so `verify_webhook_signature` returns `true` unconditionally.
3. `WebhooksController#create` dispatches to `PushHandler`, which resolves `Repository.from_github_repo_name("org-b/victim-repo")` and enqueues `GithubSyncJob` for the victim stack, syncing/advancing its commit history and potentially triggering continuous deployment — despite the request never being authenticated against `org-b`'s own credentials.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L7-17)
```ruby
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
