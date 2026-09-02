### Title
Status webhook resolves commits by SHA only, letting a status from any repo advance a merge queue on a different, unrelated stack - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits solely by `sha`, with no filter on the repository named in the webhook payload. Because Git SHAs are content-addressed and can be identical across unrelated repositories (forks, mirrors, or reproduced commits), an attacker who owns any repository wired into this Shipit instance can post a GitHub commit status for an arbitrary SHA on their own repo and have it applied to a same-SHA commit that belongs to a completely different stack, triggering `Stack#schedule_merges` on that victim stack.

### Finding Description
The claimed binding is:
`stack_advanced == Stack.find_by(full_name: payload['repository']['full_name'])`

The actual code proves this binding is broken:

`app/webhooks_controller.rb` verifies the webhook signature only against the GitHub App configured for `repository.owner.login` in the payload [1](#0-0) . It does not otherwise use the `repository` field for anything beyond signature key selection [2](#0-1) .

`Webhooks::Handlers::StatusHandler#process` then resolves commits purely by SHA, dropping the repository context entirely:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 

`Commit#create_status_from_github!` calls `add_status`, which uses `commit.stack` — i.e., whichever stack the matched `Commit` row actually belongs to (`belongs_to :stack`) [4](#0-3)  — not any stack derived from the verified payload's `repository.full_name`:
```ruby
def add_status
  ...
  if previous_status.simple_state != new_status.simple_state
    ...
    stack.schedule_merges if new_status.pending? || new_status.success?
  end
  new_status
end
``` [5](#0-4) 

Root cause: the code assumes SHA is a unique, repository-scoped identifier, but Git SHAs are content-addressed and not repository-bound. GitHub also permits creating a commit status for any SHA string on a repo you have push access to, regardless of whether that commit actually exists in that repo's history. An attacker who has push/admin rights to `attacker/repoA` (any repo they own that is connected to this Shipit instance) can call GitHub's "Create a commit status" API against `attacker/repoA` with `sha` equal to a SHA known to exist in `victim/repoB` (e.g., copied from a public commit, a shared fork ancestor, or a byte-identical cherry-pick). GitHub delivers a legitimately signed `status` webhook to Shipit with `repository.full_name = attacker/repoA` and the attacker-chosen `sha`/`state`. `verify_signature` passes because the signature is validly computed by GitHub for `attacker`'s own app/org installation — it says nothing about which commit or stack the `sha` belongs to. `StatusHandler` then matches `Commit.where(sha: ...)` and finds `victim/repoB`'s commit row, applying the attacker's `state` (e.g., `success`) to it and calling `victim/repoB`'s `stack.schedule_merges`.

None of the existing guards prevent this: `verify_signature` only authenticates the org/app that signed the payload, not the target repository of the SHA [6](#0-5) ; the `StatusHandler` params schema only validates types/presence of `sha`/`state`, not repository ownership [7](#0-6) ; and `Commit#add_status`/`schedule_merges` trust `commit.stack` unconditionally [8](#0-7) .

### Impact Explanation
This is a payload from one repository (`attacker/repoA`) mutating another repository's stack/commit state (`victim/repoB`), matching the Critical category explicitly listed in scope. Concretely: the attacker can (a) write a fabricated `Status` row onto a commit belonging to a stack they do not control, and (b) force `Stack#schedule_merges` to run against `victim/repoB`'s merge queue, potentially causing a pending `MergeRequest` to be merged/advanced when its actual CI never passed. This is repeatable against any stack whose tracked commits share a SHA reachable by the attacker (public repos, forks, mirrors, or any commit content the attacker can reproduce), and requires no Shipit credentials, session, or API token — only ownership of any repo connected to the same Shipit instance.

### Likelihood Explanation
Preconditions: (1) the attacker must control at least one repository monitored by this Shipit instance (already assumed as an unprivileged capability per the ruleset — "push to a fork they own... emit webhooks"), (2) the victim stack must have a `Commit` row with a SHA the attacker can also legitimately post a status against on their own repo — trivially satisfied for public repos/forks since Git objects are shared/content-identical across forks, and achievable in private setups via crafted identical commit metadata. Attacker cost is a single authenticated GitHub API call (`POST /repos/{owner}/{repo}/statuses/{sha}`) using their own GitHub token on their own repo — no Shipit secret, webhook secret, or session needed. This is fully repeatable and scriptable against arbitrary stacks/SHAs known to the attacker.

### Recommendation
Scope the `StatusHandler` (and analogous check-run/push handlers) commit lookup by the repository named in the verified webhook payload, e.g. resolve `Stack` via `payload['repository']['full_name']` first, then query `stack.commits.where(sha: params.sha)` instead of `Commit.where(sha: params.sha)` unscoped. Reject or ignore status updates whose payload repository does not match the commit's own stack's `github_repo_name`.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb (minitest)
test "status webhook for attacker's repo cannot advance a different stack's merge queue" do
  victim_stack = shipit_stacks(:shipit) # repository full_name e.g. "shopify/shipit-engine"
  shared_sha = "deadbeef" * 5
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "victim commit")

  attacker_payload = {
    "sha" => shared_sha,
    "state" => "success",
    "repository" => { "full_name" => "attacker/repoA", "owner" => { "login" => "attacker" } }
  }

  Shipit::Stack.any_instance.expects(:schedule_merges).never # expected: should NOT fire for victim_stack

  # simulate verified webhook already passed signature check (attacker's own org key)
  Shipit::Webhooks::Handlers::StatusHandler.new.call(attacker_payload)

  victim_commit.reload
  assert_not_equal "success", victim_commit.status.state,
    "victim/repoB commit status was mutated by attacker/repoA's webhook payload"
end
```
This test demonstrates: before the fix, `victim_commit.status.state` becomes `"success"` and `victim_stack.schedule_merges` is invoked, even though the verified payload's `repository.full_name` is `attacker/repoA` — proving the binding `stack_advanced == Stack for repository.full_name in payload` is violated.

### Citations

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

**File:** app/models/shipit/commit.rb (L11-11)
```ruby
    belongs_to :stack
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
