### Title
`StatusHandler#process` writes forged commit statuses onto any tenant's commit using only sha, with no repository/organization ownership check - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` queries `Commit.where(sha: params.sha)` across the entire database and calls `commit.create_status_from_github!(params)` on every match, without ever checking that the webhook's verified organization/repository owns the stack that commit belongs to. Any org with its own legitimately-registered `webhook_secret` can pass signature verification for itself, then submit a `status` event naming a sha that belongs to a different org's tracked stack and get a `Shipit::Status` row written on it.

### Finding Description
The broken binding the attacker exploits is: **`repository_owner_that_signed_the_request == organization_owning_stack_containing(params.sha)`** is never checked; the code only enforces `verify_webhook_signature(signature, raw_body)` against whatever org's login appears in `repository.owner.login` in the payload.

Trace:
- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) resolves `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` (line 59-62) reads `params.dig('repository','owner','login')` straight from the untrusted body, then verifies the HMAC using that org's `webhook_secret`. This only proves "the request was signed by org A's secret" - it says nothing about which stack/commit the payload's `sha` refers to.
- `StatusHandler` (`app/models/shipit/webhooks/handlers/status_handler.rb:6-25`) declares its `param_parser` with only `sha`, `state`, `description`, `target_url`, `context`, `created_at`, `branches` - `repository.full_name` is not required or read at all by this handler.
- `StatusHandler#process` then does:
```
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
with no `stacks` scoping, no `repository_name` check, no comparison to the verifying org. Contrast with `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`), which correctly scopes via `stacks.not_archived.where(branch:)` — the base `Handler#stacks`/`Handler#repository_name` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) mechanism exists precisely for this purpose, but `StatusHandler` bypasses it entirely.
- `Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) unconditionally creates a status via `statuses.replicate_from_github!(stack_id, github_status)` and `add_status` can trigger `stack.schedule_merges` (line 383) if the forged state is `success`/`pending`.

Exploit flow: Attacker registers/controls org A in Shipit with its own real `webhook_secret` (legitimate onboarding for their own CI). They observe (via public GitHub) a commit sha belonging to victim org B's tracked stack. They POST `/webhooks` with `X-Github-Event: status`, HMAC-signed with org A's secret, body `{"repository":{"owner":{"login":"org-a"}}, "sha":"<victim-sha>", "state":"success", ...}`. `verify_signature` resolves org A's app/secret via `repository_owner`, signature checks out, request proceeds. `StatusHandler#process` finds the `Commit` row for that sha (which belongs to org B's stack) and writes a forged `Status`, potentially flipping `commit.state` to success and calling `stack.schedule_merges` on org B's stack.

Existing guards that fail to prevent this: `verify_signature` only authenticates "org A signed this", not "org A owns this sha/stack"; `ExplicitParameters` schema for `StatusHandler` doesn't require or check `repository.full_name`; `drop_unhandled_event` and `check_if_ping` are irrelevant; there is no `stacks`/`repository_name` scoping call anywhere in `StatusHandler`.

### Impact Explanation
Any onboarded organization (even a small one with a legitimately obtained `webhook_secret`, i.e., an unprivileged tenant relative to other tenants) can write arbitrary `Shipit::Status` records (`description`, `target_url`, `state`) onto any other organization's commit merely by knowing a public sha, cross-tenant. This can flip `commit.state` to `success`, unblocking `Stack#schedule_merges` and influencing deploy/merge decisions for a stack it does not own. This matches the Critical category: "a payload for one repository mutating another's stack, commit, task or team." It's repeatable per-sha and works against any stack whose commit sha the attacker can learn (all public GitHub repos, and shas are inherently guessable/known once pushed).

### Likelihood Explanation
Preconditions: attacker needs their own valid, legitimately-provisioned `webhook_secret` for some org onboarded into Shipit (easily satisfiable — Shipit is often self-service for small orgs/teams), knowledge of a target commit sha (public via GitHub), and knowledge that the target stack tracks that commit (observable via Shipit's own UI/API for stacks the attacker can view, or via GitHub commit history + org name guesses). No compromise of secrets belonging to the victim is required. This is a low-cost, fully repeatable attack requiring no privileged Shipit role.

### Recommendation
`StatusHandler` must scope commit lookup to stacks owned by the repository/org that produced and verified the payload. Require `repository.full_name` in the `params` schema and change `process` to something like:
```ruby
stacks.flat_map(&:commits).select { |c| c.sha == params.sha }.each { |c| c.create_status_from_github!(params) }
```
or more efficiently, join through `Repository.from_github_repo_name(params.repository.full_name)` to constrain the `Commit.where(sha:, stack_id: repo.stacks.select(:id))` query, mirroring the pattern used in `PushHandler` via `Handler#stacks`/`#repository_name`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "does not write a status onto a commit belonging to a different repository/org" do
  org_a_repo = Shipit::Repository.create!(name: 'repo-a', owner: 'org-a')
  org_a_stack = Shipit::Stack.create!(repository: org_a_repo, environment: 'production', branch: 'master')

  org_b_repo = Shipit::Repository.create!(name: 'repo-b', owner: 'org-b')
  org_b_stack = Shipit::Stack.create!(repository: org_b_repo, environment: 'production', branch: 'master')
  victim_commit = org_b_stack.commits.create!(sha: 'deadbeef' * 5, message: 'victim commit')

  payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'repository' => { 'full_name' => 'org-a/repo-a', 'owner' => { 'login' => 'org-a' } }
  }

  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end
end
```
Currently this test would FAIL (statuses.count increases by 1) because `StatusHandler#process` never checks `payload['repository']['full_name']` against the commit's owning stack — demonstrating the cross-tenant write. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```
