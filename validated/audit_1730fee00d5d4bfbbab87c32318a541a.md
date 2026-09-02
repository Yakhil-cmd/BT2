### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` authenticates a webhook by picking the GitHub App/secret for the organization derived from the payload's `repository.owner.login` (or `organization.login`), and validates the HMAC over the full raw body against that organization's `webhook_secret`. [1](#0-0)  This only proves that the payload was sent by GitHub for *that organization's* installation — it says nothing about which repository's data may legitimately be mutated. `StatusHandler`, however, looks up the target `Commit` purely by SHA, with no scoping to the repository named in the same payload:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 

This breaks the binding: `organization/repository that authenticated the webhook == repository whose commit status is written`. Every other webhook handler (`PushHandler`, `CheckSuiteHandler`, PR handlers) first resolves `Repository.from_github_repo_name(repository_name)` and scopes to that repo's `stacks` before acting. [3](#0-2) [4](#0-3)  `StatusHandler` is the outlier that skips this scoping entirely.

### Finding Description
Git commit SHAs are content-addressed and are not unique per repository: a fork, a mirror, or a cherry-picked/rebased commit that lands identically in two different repositories will carry the same SHA. Shipit can track multiple repositories/organizations from a single instance (`Shipit.github(organization:)` is looked up per-request from the payload). [5](#0-4) 

Given two repositories tracked by the same Shipit instance — Repo A (attacker-controlled, or attacker has push/API access) and Repo B (victim, e.g. a fork parent/child of Repo A) — an attacker with legitimate write access to Repo A can:
1. Ensure Repo A shares a commit SHA with a commit Shipit is tracking in Repo B's stack (trivial via `git fetch`/cherry-pick from B into A, or if A is a fork of B).
2. Use the GitHub Statuses API (which they legitimately control for their own Repo A) to set an arbitrary status (`state: success`, arbitrary `context`) on that SHA in Repo A.
3. GitHub delivers a `status` webhook to Shipit, signed with **Repo A's organization's** `webhook_secret`. `verify_signature` validates correctly because the signature does cover this exact payload for organization A. [6](#0-5) 
4. `StatusHandler#process` then does `Commit.where(sha: params.sha)` with no repository filter, finds the matching `Commit` row belonging to Repo B's `Stack`, and calls `commit.create_status_from_github!(params)`, writing an attacker-controlled status onto Repo B's commit. [2](#0-1) [7](#0-6) 

This is a direct analog of the wstETH report's root cause: a value ("verified organization identity") is treated as if it certifies a broader binding ("this webhook may write to this specific commit/repository") that it does not actually cover — exactly the pattern the rules call out ("an organization that authenticated versus the repository that is written").

### Impact Explanation
Commit statuses drive Shipit's deployability and merge-queue gating logic: `Commit#deployable?` requires `success?` on the aggregated `Status::Group` built from `statuses` and `check_runs`, [8](#0-7)  and a status transition can trigger `stack.schedule_merges` and continuous delivery. [9](#0-8) [10](#0-9)  An attacker who can forge a `success` status for a required CI context on a victim repository's commit can push that commit through required-status gating, resulting in an **unauthorized deploy or an unauthorized merge** in a repository/organization they do not otherwise control — this is a cross-repository write and falls under the Critical impact bucket ("cross-repository writes, or an unauthorized deploy, rollback or merge").

### Likelihood Explanation
Exploitation requires: (a) the Shipit instance manages multiple repositories/organizations (a documented, supported multi-tenant configuration — see `secrets.yml`'s multiple `github:` orgs, `docs/setup.md`), and (b) a SHA collision between attacker- and victim-controlled repositories, which is easy to engineer deliberately (forks, mirrors, shared history, or cherry-picks) since SHAs are just content hashes, not proof of provenance from a specific repo. No secret, session, or GitHub App private key of Shipit is needed — only legitimate write access to a repository/org that Shipit already trusts (which is the normal, intended trust level of any tracked repo owner), making this a genuine unprivileged-attacker-across-repos scenario, not a privileged-account requirement.

### Recommendation
Scope `StatusHandler` the same way as every other handler: resolve `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, restrict the lookup to `repository.stacks.commits.where(sha: params.sha)` (or equivalently filter `Commit` by `stack_id` belonging to that repository) before calling `create_status_from_github!`, so a status can only be attributed to a commit that actually belongs to the repository the authenticated webhook was delivered for.

### Proof of Concept
1. Shipit instance configured with two orgs/repos: `victim-org/app` (tracked stack) and `attacker-org/app-fork` (a fork of `victim-org/app`, sharing commit history/SHAs), both with GitHub Apps configured with their own `webhook_secret`s per `docs/setup.md`.
2. Attacker (owner of `attacker-org/app-fork`) picks a commit SHA `S` present in both repos (any commit predating the fork, or cherry-picked).
3. Attacker calls GitHub's `POST /repos/attacker-org/app-fork/statuses/S` with `{state: "success", context: "ci/required-check"}` — this is a completely legitimate API call for a repo they own.
4. GitHub sends a `status` webhook to Shipit for `attacker-org`, correctly signed with `attacker-org`'s `webhook_secret`.
5. `WebhooksController#verify_signature` passes (organization = `attacker-org`, signature matches). [1](#0-0) 
6. `StatusHandler#process` executes `Commit.where(sha: "S")`, which returns the `Commit` record belonging to `victim-org/app`'s stack (since the SHA is shared), and writes the forged `success` status onto it. [2](#0-1) 
7. If `victim-org/app`'s `shipit.yml` requires the `ci/required-check` context, that commit becomes `deployable?` and eligible for automatic merge/continuous deployment, without any real CI having run in `victim-org/app`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
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

**File:** app/models/shipit/commit.rb (L279-287)
```ruby
    end

    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```
