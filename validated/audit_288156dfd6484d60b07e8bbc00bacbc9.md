## Analysis Result

Analysis confirms that `GithubSyncJob#perform` re-fetches commits via `stack.github_api` (which uses the stack's own repository-scoped GitHub client), and the actual state-changing effect is limited to appending commits/refreshing the cached spec for whatever `stack_id` was resolved. The key question for a valid analog was whether the organization whose `webhook_secret` authenticates a request can diverge from the repository that `Repository.from_github_repo_name` resolves for that request in `Handler#stacks`.

### Title
Cross-Organization Webhook Signature Confusion Enables Unauthorized Stack Sync — (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook using `repository_owner`, a value read directly from the untrusted JSON body, while the handlers that actually act on the payload (e.g. `PushHandler`) select the target `Stack` using a **different** field from that same untrusted body (`repository.full_name`). In a multi-organization Shipit deployment, an attacker who legitimately controls one configured GitHub organization (and therefore legitimately knows that organization's `webhook_secret`) can forge a payload whose `repository.full_name` names a stack belonging to a *different* configured organization, sign it with their own organization's secret, and have Shipit process it as if it were a genuine event for the victim organization's repository.

### Finding Description
`verify_signature` computes the signing organization purely from attacker-controlled JSON: [1](#0-0) [2](#0-1) 

`repository_owner` falls back from `repository.owner.login` to `organization.login`, both attacker-supplied fields in the raw POST body used only to pick which configured GitHub App/org's `webhook_secret` performs HMAC verification: `Shipit.github(organization: repository_owner)` then `github_app.verify_webhook_signature(...)`. [3](#0-2) 

Once the signature check passes (using whatever secret matches the attacker-chosen `repository_owner`), the dispatched handler resolves the actual target using an **independent** field, `repository.full_name`: [4](#0-3) 

`PushHandler#process` then invokes `stack.sync_github(expected_head_sha: params.after)` for every non-archived stack on the matching branch of that repository — regardless of which organization's secret validated the request: [5](#0-4) 

This is precisely the binding violation called out in scope: *"an organization that authenticated versus the repository that is written."* The signature only proves the request was signed with organization X's secret; it proves nothing about the `repository.full_name` field, which is never cross-checked against `repository_owner`/`organization.login`. Because both fields live in the same attacker-controlled JSON body and are never reconciled, an attacker who owns a legitimately configured Shipit organization can freely set `repository.full_name` to `"victim-org/victim-repo"` while keeping `repository.owner.login`/`organization.login` equal to their own org (whose secret they know), and the signature will still validate.

### Impact Explanation
Triggering `stack.sync_github` for a victim's stack causes `GithubSyncJob` to fetch commits from GitHub using the victim stack's own repository-scoped `github_api`, append new commits, and re-cache the deploy spec: [6](#0-5) 

If the victim stack has `continuous_deployment` enabled, an appended/synced commit can trigger `Stack#trigger_continuous_delivery` / `trigger_deploy`, resulting in an **unauthorized deploy** being scheduled for a repository the attacker has no legitimate access to — this satisfies the Critical impact bar ("an unauthorized deploy"). At minimum it forces unauthenticated-with-respect-to-victim-org state mutation (commit ingestion, spec cache invalidation) on a stack outside the attacker's authorization scope, crossing an organizational trust boundary that the signature check was specifically designed to enforce.

### Likelihood Explanation
Exploitability requires only that the attacker operate a second, independently configured GitHub organization/app entry in Shipit's multi-org config (a documented, supported configuration in `config/secrets.development.example.yml`) — this is an "unprivileged" position relative to the victim org, requiring no compromise of victim credentials, no `ApiClient` token, and no webhook secret belonging to the victim. The attack payload is a simple crafted POST to `/webhooks` with a valid signature for the attacker's own org. Likelihood is moderate-to-high specifically for deployments that host multiple tenant organizations under one Shipit instance, which is an explicitly supported and documented use case.

### Recommendation
Bind the field used for secret selection to the field used for resolution: after verifying the signature, re-derive `repository_owner` from `repository.full_name`'s owner segment (or vice versa) and reject the webhook (422) if they disagree. Alternately, verify the signature using the secret associated with the owner parsed from `repository.full_name` exclusively, rather than a separately-read `repository.owner.login`/`organization.login` field, so only one payload field ever drives both trust decisions.

### Proof of Concept
1. Configure Shipit for two orgs, `attacker-org` and `victim-org` (multi-org config as documented in `config/secrets.development.example.yml`), each with distinct `webhook_secret`s known respectively to each org's admins.
2. As an admin of `attacker-org` (who legitimately knows `attacker-org`'s `webhook_secret`), craft a push payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "attacker-org" }
  }
}
```
3. Compute `X-Hub-Signature` using `attacker-org`'s `webhook_secret` over the raw JSON body and POST it to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "attacker-org")` and successfully verifies the signature [1](#0-0) .
5. `PushHandler` (via `Handler#stacks`) resolves stacks for `victim-org/victim-repo` using `repository.full_name` [4](#0-3)  and calls `stack.sync_github` on the victim's stack, despite the request never being signed by `victim-org`'s secret.

### Citations

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
