### Title
Cross-repository status forgery escalates victim commits to deployable via unscoped `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target `Commit` purely by `sha`, without restricting the lookup to the repository named in the webhook payload, unlike the `Handler` base class's `stacks` helper used for repository scoping. Because git commit SHAs are content-derived and identical across forks/cherry-picks, an attacker who owns any GitHub org connected to the same Shipit instance can post a signed status webhook naming their own repository/org (passing `verify_signature`), while the `sha` field targets a commit that also exists in a victim's stack, causing a real `Status` row to be written against the victim's commit/stack.

### Finding Description
The claimed binding is: `Status` rows attributable to a stack == rows whose payload named that stack's own repository (`payload.repository.full_name == commit.stack.repository.full_name`). This does not hold.

`StatusHandler#process` is:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

This queries `Commit` globally by `sha` across every stack/repository in the installation, with no use of the `stacks`/`repository_name` scoping helper that the base `Handler` class provides:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

`commit.create_status_from_github!` then writes the status using the commit's own real `stack_id`, not any value derived from the attacker's payload:
```ruby
def create_status_from_github!(github_status)
  add_status do
    statuses.replicate_from_github!(stack_id, github_status)
  end
end
``` [3](#0-2) 

`WebhooksController#verify_signature` only checks that the request is signed for the org named in `repository.owner.login`/`organization.login` of the payload — it never checks that this org actually owns the commit's sha or the affected stack:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [4](#0-3) 

Exploit flow: attacker owns (or controls) an org/repo tracked by the same Shipit instance and knows/derives its webhook signing behavior for their own legitimate webhook events (a precondition inherent to being a tenant). They fork the victim repository (forking preserves commit SHAs bit-for-bit) or otherwise obtain a shared commit SHA. They then send (or trigger via their own GitHub repo) a `status` event where `repository.full_name`/`owner.login` names their own org, but `sha` is the shared victim commit SHA, with `state: "success"`. `verify_signature` passes because the signature is valid for the attacker's own org. `StatusHandler#process` looks up `Commit.where(sha: ...)` with no repository filter, finds the victim's `Commit` row (same sha, different stack), and creates a `Status` on it, flipping `Commit#deployable?` to true:
```ruby
def deployable?
  !locked? && (stack.ignore_ci? || (success? && !blocked?))
end
``` [5](#0-4) 

Repeating this for a sequence of blocked commits (batch) causes `Stack#next_commit_to_deploy` (private, backed by `deployable_commits`) to return a batch of commits that were never validated by the victim's real CI, which is then used to gate deploys/max-commits-per-deploy logic (`UndeployedCommit#deploy_disallowed?`, `#deploy_discouraged?`) relied upon in `app/models/shipit/undeployed_commit.rb`. [6](#0-5) 

No existing guard closes this gap: `verify_signature` verifies the request signer's identity, not the sha-to-repository binding; `drop_unhandled_event`/`ExplicitParameters` only validate payload shape (`sha`, `state`, etc.), not repository ownership of the sha; and the `Handler#stacks` scoping mechanism that would enforce this binding exists in the codebase but is simply not used by `StatusHandler`.

### Impact Explanation
An attacker who is a legitimate but unprivileged tenant of a shared Shipit instance can create arbitrary `Status` (CI result) rows on any other tenant's commits that happen to share a SHA with one of their own commits (trivially achievable via forking), forging "success" CI signals. This flips `Commit#deployable?` and thus `Stack#next_commit_to_deploy`/`deployable_commits`, enabling an unauthorized deploy of code that was never validated by the victim's real CI — matching the Critical category "a payload for one repository mutating another's stack, commit ... or an unauthorized deploy." The attack is repeatable per-sha across the entire backlog of a victim's undeployed commits, and generalizes to any victim stack sharing a fork lineage or common commit history with an attacker-controlled repository.

### Likelihood Explanation
Requires: attacker controls a repository/org already registered as a Shipit tenant (or otherwise able to produce a validly signed `status` webhook naming their own repository), and a victim stack has one or more commits sharing SHAs with attacker-reachable commits (near-guaranteed for any forked/mirrored repository, since git SHAs are pure content hashes independent of remote). No victim or Shipit secrets are needed — only the attacker's own webhook signing capability for their own repository. Cost is a handful of HTTP POSTs to `/webhooks`.

### Recommendation
Scope `StatusHandler#process` to the repository named in the webhook payload the same way other handlers use `Handler#stacks`/`repository_name`, e.g., only update statuses for `Commit`s whose `stack` is in `stacks` (derived from `payload.dig('repository','full_name')`), rejecting or ignoring cross-repository sha matches entirely.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "process does not create a status for a commit belonging to a different repository" do
  victim_stack = shipit_stacks(:shipit) # repo: "shopify/shipit-engine"
  victim_commit = victim_stack.commits.create!(sha: 'deadbeef' * 5, author: shipit_users(:shipit),
                                                committer: shipit_users(:shipit), authored_at: Time.now,
                                                committed_at: Time.now, message: 'victim commit')

  forged_payload = ExplicitParameters::Parameters.new(
    sha: victim_commit.sha,
    state: 'success',
    context: 'ci/attacker',
    repository: { full_name: 'attacker-org/attacker-repo', owner: { login: 'attacker-org' } }
  )

  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(forged_payload.to_h.deep_stringify_keys)
  end

  refute_predicate victim_commit.reload, :deployable?
end
```
Given current code, `Commit.where(sha: params.sha)` matches `victim_commit` regardless of the forged `repository.full_name`, so the `assert_no_difference` fails and `victim_commit.deployable?` becomes true — demonstrating the broken binding. Looping this over several sequential victim shas and then asserting `stack.send(:next_commit_to_deploy)` returns the forged batch demonstrates the escalation described in the question.

### Citations

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

**File:** app/models/shipit/undeployed_commit.rb (L39-45)
```ruby
    def deploy_disallowed?
      !deployable? || !stack.deployable?
    end

    def deploy_discouraged?
      stack.maximum_commits_per_deploy && index >= stack.maximum_commits_per_deploy
    end
```
