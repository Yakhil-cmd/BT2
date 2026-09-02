### Title
Cross-org webhook payload forgery forces `Commit` ingestion on a victim stack via `GithubSyncJob#append_commit` - ([File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates a webhook against the organization taken from `repository.owner.login`/`organization.login`, while `Handler#stacks` selects the target stacks using the independent `repository.full_name` field from the same JSON body. Because these are two separate attacker-controlled fields in one payload, an attacker can pass signature verification as their own secret-less org while directing the `PushHandler` to operate on a victim stack, causing `GithubSyncJob#append_commit` to persist `Commit` rows on-demand instead of only in response to the victim org's real webhook delivery.

### Finding Description
The claimed binding is: `org(repository.owner.login used in verify_signature) == org(repository.full_name used to select stacks in PushHandler)`.

Tracing the code:
- `WebhooksController#verify_signature` computes `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` and verifies the signature against `Shipit.github(organization: repository_owner)`. [1](#0-0) [2](#0-1) 
- `Handler#stacks` (base class used by `PushHandler`) resolves the target repository from a *different* field, `payload.dig('repository','full_name')`. [3](#0-2) 
- `PushHandler#process` filters those stacks by `branch` and calls `stack.sync_github(expected_head_sha: params.after)` for every matching stack. [4](#0-3) 
- `GithubSyncJob#perform` then calls `fetch_missing_commits { stack.github_commits }` and `append_commit`, which persists `stack.commits.create_from_github!(gh_commit)`. [5](#0-4) 

Because `repository.owner.login` and `repository.full_name` are two independent JSON keys the attacker fully controls in the POST body, the attacker sets `repository.owner.login` to their own secret-less org (making `verify_signature` pass trivially, since that org has no configured webhook secret) while setting `repository.full_name` to `victim-org/victim-repo`. `verify_signature` never checks that the `full_name` org matches the `owner.login` org, so the equality the code implicitly relies on does not hold. No other guard (`drop_unhandled_event`, `ExplicitParameters` schema on `PushHandler`, `force_github_authentication`, `User#authorized?`) inspects this cross-field consistency; they only validate presence of `ref`/`after` and the event type.

Given this, an unprivileged attacker who controls a secret-less GitHub org can send a crafted `push` webhook naming the victim repository's `full_name` and `branch`, at any time, triggering `GithubSyncJob` for the victim stack. `fetch_missing_commits` does pull real data from GitHub via `stack.github_api` (the victim's own credentials), so the ingested commit content is not forged — but the write itself, and its timing, is triggered by a party with no relationship to the victim org.

### Impact Explanation
Each forged request causes `stack.commits.create_from_github!` to run for an arbitrary victim stack the attacker names, writing `Commit` rows and updating stack head/spec-cache state without any authentic trigger from the victim org. This is repeatable against any known `owner/repo` + `branch` combination, independent of whether the victim org ever sent a webhook, and matches the Critical category "a payload for one repository mutating another's stack, commit, task or team." It does not, by itself, inject falsified commit content (the GitHub API call still uses the victim stack's real credentials), so the primary damage is unauthorized write-triggering/timing manipulation and stack-state churn (`mark_as_accessible!`/`mark_as_inaccessible!`, forced `CacheDeploySpecJob`), rather than data forgery.

### Likelihood Explanation
Preconditions: attacker owns or controls any GitHub organization with no webhook secret configured in `Shipit.github_teams`/app config (explicitly given as a precondition), and knows or guesses the victim's `owner/repo` full name and tracked `branch` (both public, discoverable information). No Shipit session, API token, or GitHub credentials for the victim org are needed. The attacker only needs to POST a JSON body to `/webhooks` with a forged `X-Hub-Signature` computed against their own secret (or none), which is straightforward and repeatable at will.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#stacks`), enforce that the organization used to verify the signature is the same organization embedded in `repository.full_name`/`organization.login` used for stack resolution — reject the webhook if they diverge. Alternatively, derive the repository/stack lookup key from the same verified `repository_owner` value rather than trusting an independently-controlled `full_name` field.

### Proof of Concept
Minitest plan (webhook/job integration test, no live GitHub):
1. Create `victim_org/victim_repo` `Stack` tracking `branch: "main"`.
2. Create a second, secret-less org `attacker_org` in test config (no `webhook_secret`).
3. POST to `/webhooks` with header `X-Github-Event: push`, a signature computed for `attacker_org`'s (empty) secret, and JSON body:
   - `repository.owner.login = "attacker_org"`
   - `repository.full_name = "victim_org/victim_repo"`
   - `ref = "refs/heads/main"`, `after = <sha of a real victim commit>`
4. Assert response is `200`/`204` (signature accepted) — proving `verify_signature` used `attacker_org`.
5. Assert `GithubSyncJob` was enqueued for the `victim_org/victim_repo` stack (`PushHandler` matched via `full_name`), and stub `stack.github_api`/`FirstParentCommitsIterator` to return the target commit; assert `Shipit::Commit.create_from_github!` is invoked and a `Commit` row is created on the victim stack.
6. Assert this occurred with zero interaction from `victim_org`'s real webhook secret, demonstrating `org(owner.login) != org(full_name)` while the write still succeeded.

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

**File:** app/jobs/shipit/github_sync_job.rb (L18-53)
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

    def append_commit(gh_commit)
      stack.commits.create_from_github!(gh_commit)
    end
```
