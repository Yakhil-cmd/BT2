## Title
Webhook signature verification is bound to the wrong "organization" field, allowing cross-repository webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App / webhook secret to check the HMAC signature against using `repository_owner`, which is read directly from the attacker-supplied JSON body (`repository.owner.login` or `organization.login`). Every webhook handler (`Shipit::Webhooks::Handlers::Handler` and its subclasses, e.g. `PushHandler`) then resolves the *actual* target `Stack`/`Repository` to mutate using a completely independent field of the same attacker-supplied body: `repository.full_name`. Nothing ties these two fields together, so a valid HMAC signature computed with one organization's secret can be replayed with a `repository.full_name` pointing at a stack belonging to a different organization/repository.

### Finding Description
`verify_signature` picks the app/secret to verify against like this: [1](#0-0) [2](#0-1) 

The base `Handler` class, used by every webhook event handler, resolves the target repository/stack from a **different** payload field: [3](#0-2) 

`PushHandler`, for example, uses `stacks` (derived from `repository_name` above) to run `sync_github`: [4](#0-3) 

Because `verify_signature` reads `repository.owner.login` (or `organization.login`) while `Handler#repository_name` reads `repository.full_name` — two independent keys of the same attacker-controlled raw JSON body — an attacker who is a legitimate admin of *any* organization onboarded onto this Shipit instance (and therefore knows/controls that organization's own webhook secret, since GitHub org admins configure their own app's webhook secret) can craft a raw webhook payload where:
- `repository.owner.login` = `"attacker-org"` (their own org) → signature check passes using their own org's known secret.
- `repository.full_name` = `"victim-org/victim-repo"` → the handler resolves and acts on a stack belonging to an org/repo the attacker has no access to.

This breaks the trust binding: **organization that authenticated (`repository.owner.login`) ≠ repository that is written (`repository.full_name`)**.

### Impact Explanation
This lets an attacker who legitimately controls one onboarded GitHub organization (not the victim's) forge signed webhooks against Shipit for a **different** organization's stacks. For the `push` event this triggers `GithubSyncJob` against the victim's `Stack` with an attacker-chosen `expected_head_sha`, causing Shipit to fetch commits via the victim repository's own GitHub API credentials and write them into Shipit's DB, and enqueue `CacheDeploySpecJob`: [5](#0-4) 

Because every other handler (`membership`, `status`, `check_suite`, `pull_request/*`) inherits the same `repository_name`/`stacks` resolution from `Handler`, the same cross-organization confusion applies to all webhook-driven state changes (commit statuses, check-run refreshes, PR-based review stack provisioning), not just push syncing. This can force unintended syncs/deploy-pipeline state changes on repositories/orgs the attacker does not control — an unauthorized cross-organization stack mutation gated only by knowledge of an unrelated org's own webhook secret.

### Likelihood Explanation
Requires the attacker to control (as an org owner/admin) at least one GitHub organization already configured in Shipit's `github:` multi-org secrets (a legitimate, but different, tenant of the same Shipit instance) — a realistic scenario for any Shipit deployment shared across multiple organizations/business units, since webhook secrets are set per-org by that org's own admins, not by Shipit's own operators.

### Recommendation
Verify the signature using the organization actually implied by the field used to resolve the target repository (`repository.full_name`'s owner segment), and reject the payload if `repository.owner.login`/`organization.login` disagree with the owner segment of `repository.full_name`. Alternatively, pass the already-authenticated organization down to `Handler` and require handlers to only act on repositories whose owner matches the authenticated organization.

### Proof of Concept
1. Shipit is configured with two organizations, `attacker-org` (attacker is an admin, knows its `webhook_secret`) and `victim-org` (tracks a private `Stack`).
2. Attacker crafts a raw JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org secret, body)` and sends it to `POST /webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: 'attacker-org')` and successfully verifies the signature against `attacker-org`'s own secret.
5. `PushHandler.call(params)` resolves stacks via `Repository.from_github_repo_name('victim-org/victim-repo')` and calls `stack.sync_github(expected_head_sha: ...)`, causing `GithubSyncJob` to run against `victim-org`'s stack — despite the request only having been authenticated for `attacker-org`.

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
