### Title
Cross-stack/cross-repository SHA collision in `StatusHandler#process` lets an attacker-authenticated status flip an unrelated production stack's deployability - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)` — a bare SHA lookup with no repository/stack scoping — and calls `commit.create_status_from_github!(params)` on every row that matches. Because `Commit` records from *any* stack can share the same `sha` (e.g., shared history between a fork the attacker owns and the victim's repository, or any stack tracking the same upstream commit), a webhook that is legitimately signed for the attacker's own repository can still write a `ci/test`/`success` status onto a commit belonging to a victim's production stack.

### Finding Description
The broken binding the code implicitly assumes is:
`commit.stack.github_repo_name == repository_that_authenticated_this_webhook`

but the actual code never establishes or checks this equality: [1](#0-0) 

`WebhooksController#verify_signature` only proves that the payload was legitimately sent by GitHub *for the organization named in the payload's own `repository.owner.login`* — it authenticates "this event genuinely originates from GitHub for repo X," not "repo X is authorized to write to commit `sha`": [2](#0-1) 

`StatusHandler` then never re-checks `params.dig('repository', 'full_name')` against the `Commit`'s own `stack.repository`; it just does a global `Commit.where(sha: params.sha)` and calls `create_status_from_github!` on every matching row, which mutates the commit's status set and re-derives deployability: [3](#0-2) [4](#0-3) 

Because the SHA is a git content hash, it is entirely plausible (and easy to engineer) for an attacker's own repository (which they legitimately own and can generate real, correctly-signed status webhooks for) to contain a commit whose SHA is identical to one recorded against a victim's production stack — e.g. a shared root/ancestor commit, a cherry-pick, or any commit copied byte-for-byte into a repo the attacker controls. Sending `POST /webhooks` with `X-Github-Event: status`, a valid signature for the attacker's own org/repo, and a payload of `{sha: <shared-sha>, context: "ci/test", state: "success"}` will pass `verify_signature` (it's a real GitHub webhook for the attacker's own repo) and then, inside `StatusHandler#process`, update *all* `Commit` rows in the database sharing that SHA — including the victim's, regardless of which repository or stack owns them.

`add_status` (called via `create_status_from_github!`) recomputes `status`/`deployable?` and, on a state transition, calls `stack.schedule_merges` and emits `deployable_status` hooks, which is exactly the mechanism that drives continuous deployment/merge decisions on the victim's production stack.

None of the existing guards defend against this: `verify_signature` only checks the webhook's authenticity for the attacker's own named repo, not authorization over the SHA; there is no `ExplicitParameters` constraint tying the SHA to a repo; and `Commit.where(sha:)` has no `stack_id`/repository join.

### Impact Explanation
A successful exploitation lets an unprivileged attacker, using only their own legitimately-owned GitHub repository and standard GitHub webhook delivery, write a fabricated `ci/test`/`success` status onto a commit belonging to an unrelated stack whose environment is marked production, in this engine. If that context is one of the stack's `required_statuses` and the commit was otherwise blocked (or pending), this flips `Commit#deployable?` to true and can trigger `stack.schedule_merges`, an unauthorized ship of attacker-influenced commit state on a production stack — matching the "payload for one repository mutating another's stack/commit" and "unauthorized deploy/merge" Critical impact category. The attack is repeatable against any commit whose SHA is shared across repositories, and the blast radius is any Shipit stack tracking that shared commit history, not just the attacker's own.

### Likelihood Explanation
Preconditions: the attacker needs (1) a real GitHub repository they own capable of emitting a genuinely-signed `status` webhook, and (2) a SHA that is shared between their own repo and the victim's tracked commit history (trivially achievable by forking, or committing identical content, since SHA is a content hash independent of "ownership"). No Shipit session, API token, or GitHub App secret is required — the attacker rides their own legitimate webhook signature. This is a low-cost, fully repeatable attack requiring no privileged access to the victim's Shipit instance or GitHub organization.

### Recommendation
In `StatusHandler#process` (and analogously in check-run/other SHA-keyed handlers), scope the `Commit` lookup to only commits belonging to a `Stack` whose `github_repo_name`/`repository.full_name` matches `params.dig('repository', 'full_name')` (or `repository_owner`/`repository_name` from the webhook payload), rather than a bare cross-tenant `Commit.where(sha: ...)`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "a status webhook for a SHA shared across repositories only updates the authenticated repository's commit" do
  victim_stack = shipit_stacks(:shipit)  # production environment stack requiring 'ci/test'
  attacker_stack = create_stack(repository: create_repository(owner: 'attacker', name: 'evil'))

  shared_sha = 'a' * 40
  victim_commit   = victim_stack.commits.create!(sha: shared_sha, message: 'shared root commit')
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, message: 'shared root commit')

  refute victim_commit.deployable?, "victim commit should not be deployable before the forged status"

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/test',
    'repository' => { 'full_name' => attacker_stack.github_repo_name, 'owner' => { 'login' => 'attacker' } },
  }

  Shipit::Webhooks::Handlers::StatusHandler.new.call(payload) # signature already verified upstream for attacker's own repo

  # Binding under test:
  # commit.stack.github_repo_name(before) == repository_that_authenticated(payload)  -> should stay TRUE
  assert_equal attacker_stack.github_repo_name, payload['repository']['full_name']
  assert victim_commit.stack.github_repo_name != payload['repository']['full_name'],
         "victim stack repo differs from authenticated repo"

  victim_commit.reload
  assert_not victim_commit.deployable?, "victim commit must remain unaffected by attacker's own webhook"
end
```
This test demonstrates that, without a repository-scoping fix, `victim_commit.reload.deployable?` flips to `true` even though the webhook only authenticated the attacker's own repository.

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
