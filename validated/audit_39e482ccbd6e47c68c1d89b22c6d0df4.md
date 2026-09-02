### Title
Cross-repository commit-status forgery via unscoped SHA lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the incoming payload against based solely on `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`): [1](#0-0) . This establishes the binding: *the organization whose secret authenticated the request == the repository the payload claims to belong to*.

However, `StatusHandler#process`, which handles the `status` event, never re-checks that binding when deciding **what to write**. It looks up commits purely by `sha`, globally, across every stack/repository in the installation: [2](#0-1) 

Compare this to every other handler (`PushHandler`, the `PullRequest::*` handlers), which all scope their side effects through `Repository.from_github_repo_name(payload.dig('repository','full_name'))` before touching any `Stack`/`Commit`: [3](#0-2) [4](#0-3) .

`StatusHandler` breaks this pattern: the org authenticated by `verify_signature` (via `repository.owner.login`) has no relationship at all to the `Commit` rows ultimately mutated, because `Commit.where(sha: params.sha)` is not filtered by `stack`/`repository`. Git commit SHAs are content hashes and are **not globally unique across repositories** — identical trees/parents/authors/messages/timestamps (e.g., shared upstream commits, forks, cherry-picks, or intentionally crafted commits) produce identical SHAs in unrelated repositories. Any attacker who can get a legitimately-signed `status` webhook delivered from *any* org/repo where they have push or status-setting rights (their own GitHub App installation, or a repository they control within a multi-org Shipit deployment as documented in `docs/setup.md`'s "Using Multiple GitHub Applications" section) can set an arbitrary commit status for a SHA that also exists as a tracked `Commit` in a completely different, victim `Stack`.

`Commit#create_status_from_github!` then records that forged status, feeding directly into `Commit#deployable?` and CI-gating logic (`ci.require`/blocking statuses) and into `schedule_continuous_delivery`, which can enqueue an actual deploy: [5](#0-4) [6](#0-5) [7](#0-6) .

### Impact Explanation
This crosses the "an organization that authenticated versus the repository that is written" boundary explicitly called out as in-scope. By forging a `success` status for a shared-SHA commit in a victim stack, an attacker with no privileges on the victim's repository can flip `deployable?` to `true` for a commit that GitHub's CI never actually approved, and — if `continuous_deployment` is enabled on that stack — trigger `ContinuousDeliveryJob`, resulting in an **unauthorized deploy**. This satisfies the "Critical" impact bar defined in the rules (unauthorized deploy).

### Likelihood Explanation
Exploitation requires: (1) the target Shipit instance operates in multi-GitHub-App/org mode (documented, supported configuration) or otherwise processes webhooks from a repo/org the attacker controls; and (2) the attacker can produce or acquire a commit whose SHA collides with a commit already tracked by the victim `Stack` (trivial for forked/shared-history repositories, which is a common real-world scenario for organizations sharing upstream code, vendored branches, or cherry-picked commits) and can trigger a `status` event referencing that SHA from their own controlled repository. No secret, session, or repository-write access on the *victim* repo is needed — only on the attacker's own repo/org, which is the "unprivileged attacker" starting point.

### Recommendation
Scope `StatusHandler#process` (and any other handler that queries by SHA) to the repository asserted in the payload, mirroring the pattern used by `Handler#stacks`/`repository_name`, e.g. `stacks.joins(:commits).where(shipit_commits: { sha: params.sha })` instead of the unscoped `Commit.where(sha: params.sha)`. Additionally, verify that the repository referenced in the payload actually belongs to the organization whose webhook secret validated the request, rather than trusting `repository.owner.login` purely for secret selection.

### Proof of Concept
1. Attacker controls repository `attacker-org/repo` with the Shipit GitHub App installed (its own `webhook_secret`).
2. Attacker crafts (or naturally produces, e.g. via a shared/forked commit history) a commit whose SHA `S` is identical to a commit already present in victim `Stack` (`victim-org/app`) tracked by the same Shipit instance.
3. Attacker sets a commit status via the GitHub API on `attacker-org/repo` for SHA `S` (`state: success`, matching a required CI context such as `ci/circleci`), which GitHub delivers as a `status` webhook signed with `attacker-org`'s own webhook secret.
4. `WebhooksController#verify_signature` resolves `repository_owner` from the payload's `repository.owner.login` = `attacker-org`, validates the signature correctly against `attacker-org`'s secret, and proceeds.
5. `StatusHandler#process` executes `Commit.where(sha: 'S').each { |commit| commit.create_status_from_github!(params) }` — this matches the `Commit` row belonging to `victim-org/app`, not `attacker-org/repo`, and records a fabricated "success" status on it.
6. If the victim stack has continuous deployment enabled and this status satisfies its required-status gating, `Commit#schedule_continuous_delivery` enqueues `ContinuousDeliveryJob`, producing an unauthorized deploy triggered entirely by the attacker's own webhook traffic.

Note: I was unable to fully verify from the indexed code whether `Repository.from_github_repo_name` normalization or any additional cross-checks exist elsewhere in the request pipeline that might mitigate this (e.g., in `GithubSyncJob` or a global before-filter not surfaced by search); a full audit of `app/jobs/shipit/github_sync_job.rb` and the complete webhook dispatch path would be advisable to confirm no additional repository-scoping occurs before `StatusHandler#process` runs.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
