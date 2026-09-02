### Title
Cross-repository CI-status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates a `status` webhook against the GitHub App configured for the organization named in the payload's `repository.owner.login` (or `organization.login`) field. That authentication only proves the payload was signed by *that* organization's webhook secret. But the handler that actually writes the status, `StatusHandler#process`, does not scope its write to the repository that was authenticated — it matches and mutates **any** `Commit` row anywhere in the database whose `sha` equals the attacker-controlled `params.sha`. This breaks the binding: organization that authenticated == repository that is written.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb#L24-L49` derives `repository_owner` from the JSON body and verifies the HMAC signature using `Shipit.github(organization: repository_owner)`: [1](#0-0) [2](#0-1) 

Signature verification itself only proves the message was signed with the secret configured for that one organization: [3](#0-2) 

Once verified, `create` dispatches the parsed body to every registered handler for the event, passing the whole payload through unmodified: [4](#0-3) 

`StatusHandler#process`, however, ignores which repository the payload's `repository`/`organization` fields describe entirely, and instead does a global lookup by `sha` across the whole `Commit` table: [5](#0-4) 

Because Git commit SHAs are content-derived and are reused verbatim across forks, mirrors, and cherry-picked/rebased branches, an attacker who legitimately controls a GitHub organization/repository with its own valid webhook secret (or an org for which no `webhook_secret` was ever configured — in which case `verify_webhook_signature` trivially returns `true` per the early-return above) can trigger a `status` event whose `sha` matches a commit that actually belongs to a completely different Shipit stack/repository/organization. `StatusHandler` will then write a forged CI status (e.g. `state: 'success'`) onto that unrelated commit via `Commit#create_status_from_github!`.

### Impact Explanation
Commit CI status directly gates automated actions: `Stack#branch_status`/`#merge_status`/`#allows_merges?` and `MergeRequest#reject_unless_mergeable!`/`#all_status_checks_passed?` all consume `Commit#status`/`Commit#state` computed from these `statuses` rows: [6](#0-5) [7](#0-6) [8](#0-7) 

By forging a `success` status on a commit belonging to a stack the attacker never authenticated against, the attacker can unblock the merge queue (`allows_merges?`) or clear `any_status_checks_missing?`/`any_status_checks_failed?` gates on a `MergeRequest`, leading to an **unauthorized merge or deploy** of code the attacker does not control — this satisfies the Critical/High "unauthorized deploy, rollback or merge" impact bar, since it lets an unprivileged organization owner (of an unrelated, attacker-controlled org/repo) affect deploy/merge decisions in a target repository they have no write access to.

### Likelihood Explanation
Exploitation requires the attacker to control any GitHub organization/repository that is configured in this Shipit instance (a very low bar — Shipit instances typically host many teams/orgs under one deployment, and multi-tenant orgs commonly do not each configure a distinct `webhook_secret`, in which case verification is unconditionally bypassed per `return true unless webhook_secret`). The attacker only needs a commit SHA that exists in both their own repo and the victim stack's repo — trivially achievable via forking the victim repository (fork commits retain identical SHAs) or via a shared upstream/mirror relationship, which is a common Shipit deployment pattern (stacks per fork/branch). No GitHub App private key, webhook secret of the victim org, or Shipit session is required.

### Recommendation
`StatusHandler#process` must scope the `Commit` lookup to the repository indicated by the authenticated payload (e.g., `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { owner: repository_owner, name: params.repository_name })`), not a bare `Commit.where(sha:)` across all stacks. More generally, every webhook handler should re-derive and enforce that the `repository`/`organization` field it acts on matches the organization that was cryptographically verified in `WebhooksController#verify_signature`, rather than trusting handlers to independently re-derive scope from payload data that was never part of the trust decision.

### Proof of Concept
1. Attacker controls (or forks into) GitHub org `attacker-org`, which is registered in this Shipit instance's `secrets.github` config but has no `webhook_secret` set (or has its own valid secret).
2. Victim Shipit stack tracks `victim-org/app`, with a commit `abc123...` currently pending CI (e.g. required status `ci/travis` missing).
3. Attacker forks `victim-org/app` into `attacker-org/app` (or otherwise obtains a repo containing the identical commit `abc123...`), then sends (or has GitHub deliver, since no secret is required for `attacker-org`) a `status` webhook to `POST /webhooks` with:
   - `X-Github-Event: status`
   - body: `{"sha":"abc123...","state":"success","context":"ci/travis","repository":{"owner":{"login":"attacker-org"}}}`
4. `WebhooksController#verify_signature` looks up `Shipit.github(organization: "attacker-org")` and passes (secret absent → `verify_webhook_signature` returns `true`, or attacker signs with their own valid secret).
5. `StatusHandler#process` executes `Commit.where(sha: "abc123...")`, finds the victim's commit record (same SHA, different stack/repository), and calls `create_status_from_github!`, marking `ci/travis` as `success` on the victim's commit.
6. The victim stack's `MergeRequest#reject_unless_mergeable!`/`allows_merges?` now see the forged passing status and permit an unauthorized merge/deploy on `victim-org/app`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-24)
```ruby
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/stack.rb (L286-300)
```ruby
    def merge_status(backlog_leniency_factor: 2.0)
      return 'locked' if locked?
      return 'failure' if %w[failure error].freeze.include?(branch_status)
      return 'backlogged' if backlogged?(backlog_leniency_factor:)

      'success'
    end

    def backlogged?(backlog_leniency_factor: 2.0)
      maximum_commits_per_deploy && (undeployed_commits_count > maximum_commits_per_deploy * backlog_leniency_factor)
    end

    def branch_status
      undeployed_commits.each do |commit|
        state = commit.status.simple_state
```

**File:** app/models/shipit/stack.rb (L376-382)
```ruby
    def deployable?
      !locked? && !active_task? && !awaiting_provision? && deployment_checks_passed?
    end

    def allows_merges?
      merge_queue_enabled? && !locked? && merge_status == 'success'
    end
```

**File:** app/models/shipit/merge_request.rb (L155-206)
```ruby
    def reject_unless_mergeable!
      return reject!('merge_conflict') if merge_conflict?
      return reject!('ci_missing') if any_status_checks_missing?
      return reject!('ci_failing') if any_status_checks_failed?
      return reject!('requires_rebase') if stale?

      false
    end

    def merge!
      raise InvalidTransition unless pending?

      raise NotReady if not_mergeable_yet?

      stack.github_api.merge_pull_request(
        stack.github_repo_name,
        number,
        merge_message,
        sha: head.sha,
        commit_message: 'Merged by Shipit',
        merge_method: stack.merge_method
      )
      begin
        if stack.github_api.pull_requests(stack.github_repo_name, base: branch).empty?
          stack.github_api.delete_branch(stack.github_repo_name, branch)
        end
      rescue Octokit::UnprocessableEntity
        # branch was already deleted somehow
      end
      complete!
      true
    rescue Octokit::MethodNotAllowed # merge conflict
      reject!('merge_conflict')
      false
    rescue Octokit::Conflict # shas didn't match, PR was updated.
      raise NotReady
    end

    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```
