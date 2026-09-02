### Title
StatusHandler resolves `params.sha` globally without repository scoping, allowing cross-repository status forgery - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits solely by `Commit.where(sha: params.sha)` with no constraint tying the match to the webhook's own repository. Since GitHub commit SHAs are public, deterministic, content-addressed values (and identical across forks/shared history), any GitHub user who owns a repository with a signed webhook installation can forge a `CommitStatus` on a commit belonging to a completely different stack/repository they do not control.

### Finding Description
The broken binding: `verify_signature`'s repository scope (`repository_owner` from the attacker's own payload, matched against `Shipit.github(organization: repository_owner)`) is expected to equal the repository scope of the row mutated by `process`, i.e. `commit.stack.repository == payload.repository`. It does not.

`StatusHandler` declares only type constraints, no length/format/repository constraint: [1](#0-0) 

`process` then resolves commits with a bare equality across the entire `commits` table, with no `stack_id`/`repository` filter: [2](#0-1) 

`WebhooksController#verify_signature` only proves that the request was signed with the webhook secret of the *sender's* GitHub App installation/organization (`repository_owner`, derived straight from the attacker-controlled payload); it never checks that the SHA in the payload belongs to that same repository: [3](#0-2) [4](#0-3) 

Root cause: Shipit's `Commit#sha` uniqueness/identity is only meaningful per-stack (`belongs_to :stack`), but `StatusHandler` never joins/filters on `stack`/repository, and `create_status_from_github!` unconditionally applies the attacker-supplied `state`/`description`/`target_url`/`context` to whatever commit matched: [5](#0-4) [6](#0-5) 

Exploit flow: an attacker who owns/administers any repository that has the Shipit GitHub App installed (this yields a legitimately signed webhook for their own repository, no Shipit secret needed) sends a `status` event where `sha` is a real, publicly-known commit SHA copied from the victim repository's commit history (e.g., a shared ancestor commit that predates a fork, a cherry-picked commit, or any commit whose SHA the attacker read off GitHub's public UI/API for the target repo) and `state: "success"`. Because `Commit.where(sha: params.sha)` is not scoped, this matches the victim's `Commit` row in an entirely unrelated stack, and `create_status_from_github!` writes a forged success status on it. If that status is one of the stack's `required_statuses`/`blocking_statuses`, this can flip `Commit#deployable?` to true and trigger `schedule_continuous_delivery`, causing an unauthorized deploy of the victim stack.

None of the existing guards prevent this: `verify_signature` validates the sender's own signature/organization, not the target of the SHA lookup; `drop_unhandled_event` only filters by event type; there is no `ExplicitParameters` length/format validator on `sha`; and no model validation ties `Commit#sha` uniqueness or lookup to a specific repository in this handler.

### Impact Explanation
A payload legitimately signed for repository A can mutate commit-status state for a commit belonging to repository/stack B, matching the rule "a payload for one repository mutating another's stack, commit, task or team." Because a forged success status can satisfy required/blocking status checks, this can escalate to triggering an unauthorized deploy on the victim stack (Critical). The attack is repeatable against any commit SHA the attacker can learn (which is always public GitHub information) and against any stack configured in the same Shipit instance, so blast radius spans the whole multi-tenant deployment.

### Likelihood Explanation
Preconditions: the attacker needs a repository with the Shipit GitHub App/webhook installed on it (something available to any GitHub user who can install a public GitHub App on their own repo, or simply push/own a repo that already has the integration configured), and knowledge of a target commit SHA, which is always public. No Shipit session, API token, or secret is required. This makes the attack low-cost and fully repeatable.

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and analogous handlers such as `check_suite_handler.rb`) to the repository identified by the payload, e.g. resolve the `Stack`/`Repository` from `params.repository` (owner/name) first, then query `stack.commits.where(sha: params.sha)` instead of a bare `Commit.where(sha: params.sha)`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual additions)
test "status payload for repo A does not update a commit belonging to repo B's stack" do
  stack_a = shipit_stacks(:shipit)
  stack_b = shipit_stacks(:cloudhead) # different repository/stack fixture

  shared_sha = "a" * 40
  commit_b = stack_b.commits.create!(sha: shared_sha, message: "shared ancestor")

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/forged',
    'repository' => { 'full_name' => stack_a.github_repo_name, 'owner' => { 'login' => stack_a.repository.owner } }
  }

  # sanity: binding as claimed
  assert_equal [], Shipit::Commit.where(sha: shared_sha, stack_id: stack_a.id)
  assert_equal [commit_b], Shipit::Commit.where(sha: shared_sha).to_a

  Shipit::Webhooks::Handlers::StatusHandler.new(payload, delivery: 'x', event: 'status').process

  commit_b.reload
  # FAILS today: commit_b (stack B) receives a status even though the signed
  # payload only proves authorship for stack A's repository.
  assert_nil commit_b.statuses.find_by(context: 'ci/forged'),
    "status handler mutated a commit belonging to an unrelated repository/stack"
end
```
This demonstrates that `Commit.where(sha: params.sha)` matches rows outside the payload's own repository, and that `StatusHandler#process` writes to them without any repository-scoping check.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
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
```

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
