### Title
Webhook signature is verified against the organization of `repository.owner.login`, but every event handler resolves and writes to whatever repository is named in `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App/HMAC secret to validate a webhook against using `repository.owner.login` (falling back to `organization.login`), but every `Shipit::Webhooks::Handlers::*` class that actually mutates state (creates commits, syncs a stack, opens/archives review stacks) resolves the target `Repository`/`Stack` using the independent `repository.full_name` field from the same payload. The signature check and the write target are bound to two different fields of the same attacker-influenced JSON body, exactly the "organization that authenticated versus the repository that is written" mismatch class.

### Finding Description
`verify_signature` computes the org used for HMAC verification like this: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` selects, per Shipit's multi-org configuration, the `webhook_secret` used to HMAC-verify the raw payload: [3](#0-2) 

Critically, `verify_webhook_signature` returns `true` unconditionally when the org's `webhook_secret` is blank/`nil` - which is the documented default in every example config shipped with the engine (`config/secrets.development.example.yml`, `docs/setup.md`, `template.rb`, `test/dummy/config/secrets_double_github_app.yml` all show `webhook_secret:` unset).

Once verification passes (or is bypassed for an org with no secret configured), the event is dispatched to a handler. Every handler resolves its target repository from a *different* field of the same payload - `repository.full_name` - completely independent of the `repository.owner.login`/`organization.login` field used for signature verification: [4](#0-3) [5](#0-4) 

The `PushHandler` then triggers `stack.sync_github(expected_head_sha: params.after)` for whatever `Stack` matches `repository.full_name` + branch, which enqueues `GithubSyncJob` and ultimately appends attacker-influenced-looking commit references and re-caches the deploy spec for that stack: [6](#0-5) 

Because the field gating "is this webhook allowed to speak for org X" (`repository.owner.login`) is never checked against the field that decides "which repository/stack gets mutated" (`repository.full_name`), an attacker who controls an organization/repo that Shipit is configured to trust (as one of several orgs under the multi-org `github:` key, per `docs/setup.md`, `Shipit::GitHubApp`) - and for which no `webhook_secret` is set, or whose secret the attacker knows because they administer that org's GitHub App - can submit a POST to `/webhooks` with:
- `repository.owner.login` = their own (trusted-but-secretless) org, so `verify_webhook_signature` returns `true`.
- `repository.full_name` = `victim-org/victim-repo`, an arbitrary *other* repository already tracked by a `Stack` in the same Shipit instance.

The push/pull_request/check_suite handlers will act on the victim stack: forcing a `GithubSyncJob` sync against an `expected_head_sha` the attacker chooses, or (via `PullRequest::ReviewStackAdapter`/`OpenedHandler`) creating/archiving review stacks for the victim repository, or injecting fabricated commit-status/check-run state for it.

### Impact Explanation
This breaks the deployment-trust binding between "the organization whose credentials authenticated this webhook" and "the repository whose state gets written," letting an attacker who only controls an unrelated, less-trusted org configured in the same Shipit instance push/sync/manipulate a victim organization's `Stack`. Depending on which handler is reached this can force a `sync_github` run that changes which commit is considered the head of a branch and re-caches the `shipit.yml`-derived deploy spec (`CacheDeploySpecJob`), or create/archive review stacks for a repository the attacker does not control - a cross-repository write across trust boundaries within the same Shipit deployment.

### Likelihood Explanation
Requires: (1) a Shipit deployment configured with more than one GitHub App/organization (documented and supported: `docs/setup.md`, `lib/shipit/github_app.rb`), and (2) at least one of those configured organizations without a `webhook_secret` set - which is the default/example configuration shown everywhere in the repo's own setup docs and templates. Given that, exploitation requires no privileged access to the victim repository at all - only the ability to send an HTTP POST to the public `/webhooks` endpoint with a crafted JSON body and `X-Github-Event`/`X-Hub-Signature` headers (the latter can be omitted/anything if the matched org has no secret). This is realistically reachable in any multi-org Shipit install that hasn't set `webhook_secret` for every configured org.

### Recommendation
Bind signature verification and repository resolution to the same trust anchor: after selecting the GitHub App/secret via `repository_owner`, validate that `repository.full_name`'s owner segment matches `repository_owner` (and ideally the numeric `repository.id`/`organization.id` against Shipit's stored `Repository#github_id`) before dispatching to any handler. Reject the webhook if these fields disagree. Additionally, require `webhook_secret` to be present for every configured organization (fail closed rather than "return true unless webhook_secret").

### Proof of Concept
1. Configure Shipit with two orgs under `github:` (as in `docs/setup.md`): `AttackerOrg` (no `webhook_secret` set) and `VictimOrg` (has a `Stack` tracking `VictimOrg/app`).
2. Attacker (who only administers `AttackerOrg`, has no access to `VictimOrg`) sends:
```
POST /webhooks
X-Github-Event: push

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "full_name": "VictimOrg/app",
    "owner": { "login": "AttackerOrg" }
  }
}
```
3. `verify_signature` calls `Shipit.github(organization: 'AttackerOrg')`; since `AttackerOrg`'s `webhook_secret` is blank, `verify_webhook_signature` returns `true` regardless of body/signature [7](#0-6) .
4. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name('VictimOrg/app')` [8](#0-7)  and calls `stack.sync_github(expected_head_sha: '<attacker-chosen sha>')` on the victim's stack, entirely outside any credential the attacker legitimately holds for `VictimOrg`.

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
