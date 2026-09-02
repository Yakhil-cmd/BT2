### Title
Cross-repository status forgery via unscoped `sha` lookup unblocks unauthorized deploys - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits to attach a GitHub status to using only `sha`, with no check that the webhook's `repository` field matches the stack/repository that owns that commit. Because commit SHAs are shared across all forks of a repository, an attacker who controls *any* repository tracked by the same Shipit instance (e.g., a fork of the victim stack S2) can emit a genuinely-signed `status` webhook from their own repository for a shared ancestor commit, with an attacker-chosen `context`, and have it recorded against S2's commit — clearing `Commit#blocked?` for S2.

### Finding Description
Binding claimed/required: `context` string on a `Status` attached to S2's commit == a status genuinely emitted by CI running on **S2's own repository** for that commit.

Code path:
- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) validates the HMAC signature against `Shipit.github(organization: repository_owner)`, where `repository_owner` is read straight from the attacker-controlled JSON body (`params.dig('repository','owner','login')`, line 61). This only proves the request came from *some* GitHub organization configured in this Shipit instance — not that it came from S2's organization/repository specifically.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`):
```
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
This performs **no filter on repository, stack, or owning organization** — any `Commit` record anywhere in the Shipit database with a matching `sha` receives the forged status via `commit.create_status_from_github! → statuses.replicate_from_github!` (`app/models/shipit/commit.rb:165-169`).
- `Status::Common#blocking?` / `#required?` (`app/models/shipit/status/common.rb:46-51`) trust `context` purely by checking membership in `commit.blocking_statuses` / `commit.required_statuses`, which delegate to the **commit's own stack's** `deploy_spec` (`app/models/shipit/commit.rb:57-58`, `app/models/shipit/deploy_spec.rb:194-204`) — i.e., S2's configuration, not the sender's.
- `Commit#blocked?` (`app/models/shipit/commit.rb:231-237`) evaluates `stack.commits.reachable...any?(&:blocking?)` over S2's own commits.

Exploit flow: since Shipit is a shared, multi-tenant deploy tool, an unprivileged attacker who controls a repository already onboarded onto the same Shipit instance (e.g., by forking the public victim repo S2, or owning an unrelated repo in an org Shipit already tracks) can:
1. Fork S2 (or otherwise obtain/create a repository sharing a commit SHA with S2, trivial via forking since Git SHAs are preserved across forks).
2. Use their own repo's legitimate push/API access to create a commit status (`POST /repos/:owner/:repo/statuses/:sha`) with `state=success` and `context` equal to a value present in S2's `deploy_spec.blocking_statuses`/`required_statuses` (discoverable from S2's public checks tab).
3. GitHub sends a real, correctly-signed `status` webhook to Shipit, signed with the attacker's own organization's webhook secret — passing `verify_signature` because the signature check only validates "this org emitted this payload," not "this org owns this commit/repo."
4. `StatusHandler#process` matches the shared `sha` against S2's `Commit` row (no repo scoping) and writes the forged status onto it.
5. `Commit#blocked?`/`deployable?` for S2 now evaluate the forged, attacker-authored status as if it came from S2's own CI, clearing the block and enabling deploy.

None of the existing guards catch this: `verify_signature` only authenticates the sending organization, not the target commit's ownership; `ExplicitParameters` on `StatusHandler` only validates types/presence of `sha`/`state`/`context`, not repository binding; there is no `Repository`/`Stack` scoping anywhere in `StatusHandler#process`.

### Impact Explanation
A payload sent under one repository's/organization's identity mutates another repository's `Commit`/`Status` state, directly satisfying the "payload for one repository mutating another's stack/commit" and "unauthorized deploy" Critical categories. The attacker can precisely target any stack whose `blocking_statuses`/`required_statuses` context strings they can guess (these are conventional/public strings), clearing CI gates and enabling an unauthorized deploy of S2. This is repeatable against any repository sharing history (fork relationship) with a stack tracked on the same Shipit instance — a broad blast radius in any organization using Shipit for multiple teams/repos, which is the tool's normal deployment model.

### Likelihood Explanation
Preconditions: (1) the target repository S2 is public or forkable (stated in the prompt), so shared SHAs are trivially obtainable; (2) the attacker's own repository is already onboarded to the same Shipit instance (common in company-wide Shipit deployments) or is capable of producing a validly-signed webhook for an org Shipit trusts. No Shipit session, API token, or secret is required — the attacker uses their own legitimate, unprivileged GitHub push/API access to their own fork. Cost is low: one fork, one `statuses` API call. Fully repeatable per target commit/context.

### Recommendation
Scope `StatusHandler#process` (and the equivalent check-runs handling) to the repository indicated in the webhook payload: resolve the target `Stack`/`Repository` from `params['repository']['full_name']` (already verified against `repository_owner` during signature check) and restrict the `Commit.where(sha:)` lookup to commits belonging to stacks whose `Repository` matches that verified full name, rejecting/ignoring updates for commits belonging to any other repository.

### Proof of Concept
Minitest (`test/models/webhooks/handlers/status_handler_test.rb`, illustrative — actual file location should follow repo's test layout):
```ruby
test "status webhook from repository A must not clear blocking status for a shared-sha commit belonging to repository B" do
  stack_b = shipit_stacks(:shipit) # victim S2
  stack_b.update!(cached_deploy_spec: DeploySpec.new('ci' => { 'blocking' => ['ci/circleci'] }))
  shared_sha = 'deadbeef' * 5
  commit_b = stack_b.commits.create!(sha: shared_sha, message: 'shared ancestor')

  assert commit_b.blocking_statuses.include?('ci/circleci')

  # Forged params: as if sent from an unrelated repository "attacker/evil", but sharing sha with S2
  params = ActionController::Parameters.new(
    sha: shared_sha, state: 'success', context: 'ci/circleci'
  )

  Shipit::Webhooks::Handlers::StatusHandler.new(params).call

  commit_b.reload
  refute commit_b.blocked?, "forged status from an unrelated repository should not clear S2's blocking status"
end
```
Both sides of the equality: before the fix, `commit_b.blocked?` becomes `false` after processing a status whose originating repository was never checked against `commit_b.stack.repository`, proving the binding "context authenticity == CI on S2's own repository" is broken. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/commit.rb (L57-58)
```ruby
    delegate :broadcast_update, :github_repo_name, :hidden_statuses, :required_statuses, :blocking_statuses,
             :soft_failing_statuses, to: :stack
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L231-237)
```ruby
    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/status/common.rb (L46-51)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end

      def required?
        commit.required_statuses.include?(context)
```

**File:** app/models/shipit/deploy_spec.rb (L194-204)
```ruby
    def required_statuses
      (Array.wrap(config('ci', 'require')) + blocking_statuses).uniq
    end

    def soft_failing_statuses
      Array.wrap(config('ci', 'allow_failures'))
    end

    def blocking_statuses
      Array.wrap(config('ci', 'blocking'))
    end
```
