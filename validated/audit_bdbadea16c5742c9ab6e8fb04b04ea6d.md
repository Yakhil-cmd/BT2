### Title
Cross-repository CI status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up the target `Commit` purely by SHA, with no check that the SHA actually belongs to the repository named in the webhook payload that was cryptographically verified. This breaks the same class of binding as the reported bug (a value that is checked/authorized diverging from the value actually acted upon): the webhook signature authenticates the *organization* named in `repository.owner.login`, but the handler writes a `Status` to whatever `Commit` row in the *entire* database happens to share the attacker-controlled `sha` field, regardless of which stack/repository that commit belongs to.

### Finding Description
`WebhooksController#verify_signature` resolves the GitHub App/secret to use for HMAC verification from the payload's own `repository.owner.login` (falling back to `organization.login`), then verifies the signature against that org's secret: [1](#0-0) 

This only proves "this JSON blob was sent by GitHub on behalf of organization X". It says nothing about which specific repository/commit the payload is allowed to affect. That secondary binding is normally enforced by each handler via `Handler#stacks`, which scopes lookups to the `Repository` matching `payload.dig('repository', 'full_name')`: [2](#0-1) 

`PushHandler` and `CheckSuiteHandler` correctly use this `stacks` scope before touching any commit: [3](#0-2) [4](#0-3) 

`StatusHandler`, however, never calls `stacks`/`repository_name` at all — it queries `Commit` globally by `sha`: [5](#0-4) 

Because git commit SHAs are content-addressed, any commit shared between a victim's repository and a fork/mirror of it (e.g. the common history before the attacker's fork diverged) has an identical SHA in both repositories. An organization that is legitimately onboarded to this Shipit instance (i.e., has the GitHub App/webhook installed on at least one of its own repositories, satisfying `verify_signature`) can trigger a genuine, correctly-signed `status` webhook for its own fork with a `sha` value equal to a shared/upstream commit. `StatusHandler` will happily attach that status to the matching `Commit` record for the *victim's* stack as well, since the lookup is not scoped to the repository that was authenticated.

The resulting `Status` row feeds directly into deploy/merge eligibility: `Commit#deployable?` and `StatusChecker`/`MergeRequest#any_status_checks_failed?` rely on `commit.statuses` to gate deploys and the merge queue: [6](#0-5) 

### Impact Explanation
An attacker who controls an org/repo already onboarded to the Shipit instance (no privileged Shipit session, `ApiClient` token, or knowledge of any secret is required — the signature is computed and sent by GitHub itself for the attacker's own legitimate repository) can forge a "success" CI status on a commit belonging to a different stack/repository they do not control, as long as that commit's SHA is shared history (a very common situation for public/forked repositories). This can satisfy required-status checks and enable an unauthorized deploy or an unauthorized pull-request merge on the victim stack — matching the Critical "unauthorized deploy/merge" impact bucket.

### Likelihood Explanation
Requires the attacker to be a legitimate GitHub org member for any org already using this Shipit instance (unprivileged relative to the victim stack), and requires a shared-history commit SHA between the attacker's repository and the victim's — realistic for forks, mirrors, or shared base branches, and trivially engineerable by forking the victim repo before Shipit even needs to know about the fork.

### Recommendation
In `StatusHandler#process` (and any other handler that doesn't use `Handler#stacks`), scope the `Commit` lookup to the repository identified by `payload.dig('repository', 'full_name')` (i.e., filter through `stacks`/`Repository.from_github_repo_name(repository_name)`) before matching by SHA, so a status can only be applied to commits belonging to the authenticated repository.

### Proof of Concept
1. Attacker forks victim's public repository `victim-org/app` into `attacker-org/app`, sharing commit `abc123...` with upstream.
2. Attacker triggers a real GitHub status update (e.g., via the GitHub API with their own token) on commit `abc123...` in `attacker-org/app`, setting state `success`.
3. GitHub delivers a `status` webhook to Shipit signed with `attacker-org`'s configured webhook secret; `WebhooksController#verify_signature` accepts it because `repository.owner.login == "attacker-org"` is a valid, onboarded org.
4. `StatusHandler#process` runs `Commit.where(sha: "abc123...")`, which matches the `Commit` row belonging to `victim-org/app`'s stack (same SHA, different repo), and calls `create_status_from_github!`, injecting a forged `success` status.
5. If `abc123...` was blocking deploy/merge on `victim-org/app`'s stack due to a missing/failing required status, it now appears satisfied, permitting an unauthorized deploy or merge queue advance.

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/merge_request.rb (L199-206)
```ruby
    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```
