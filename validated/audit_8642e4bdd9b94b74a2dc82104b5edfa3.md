### Title
Global `Commit.where(sha:)` scan in `StatusHandler#process` lets any authenticated repository write forged Status content onto commits belonging to a completely different stack/repository - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` matches incoming `status` webhooks against **every** `Commit` in the database by `sha` alone, with no scoping to the repository/stack that the webhook's signature actually authenticated. Because git commit SHAs are content hashes shared across forks/mirrors of a repository, an attacker who owns any repository connected to Shipit can cause a real, correctly-signed GitHub webhook to be emitted from their own repo (e.g., via the GitHub Statuses API against a shared ancestor commit) that writes attacker-chosen `description`, `target_url`, and `context` into a `Shipit::Status` row owned by a victim stack.

### Finding Description
The binding that should hold is: `Status.stack_id (and the commit it decorates) == the repository that verify_signature authenticated for this request`. In reality the code enforces only:

`Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [1](#0-0)  - this proves the payload was genuinely signed by GitHub for `repository_owner`'s org/app installation, taken from `params.dig('repository','owner','login')` [2](#0-1) . It says nothing about which `stack`/`Commit` the event is allowed to touch.

`StatusHandler#process` then does a completely unscoped lookup:
```
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [3](#0-2) 

This iterates over **every** `Commit` row across **all** stacks whose `sha` matches the attacker-supplied `sha` field - there is no `stack_id`/`repository` filter tying the match back to `repository_owner`/`repository.full_name` from the same payload.

`create_status_from_github!` then writes the request body's `description`, `target_url`, and `context` verbatim into a new `Status` scoped to the matched commit's *own* stack:
```
def create_status_from_github!(github_status)
  add_status { statuses.replicate_from_github!(stack_id, github_status) }
end
``` [4](#0-3) 
```
def replicate_from_github!(stack_id, github_status)
  find_or_create_by!(
    stack_id:, state: github_status.state, description: github_status.description,
    target_url: github_status.target_url, context: github_status.context,
    created_at: github_status.created_at
  )
end
``` [5](#0-4) 

**Attack flow (no Shipit secret needed):** the attacker owns/administers Repo A, which is a legitimate, GitHub-integrated stack in this Shipit instance (this is the only precondition — no `webhook_secret`, `api_clients_secret`, or privileged Shipit role is required). Repo A is a fork/mirror of victim Repo B (also tracked as a Shipit stack), sharing ancestor commits and thus identical SHAs. The attacker calls the real GitHub Statuses API (`POST /repos/attacker/repoA/statuses/:sha`) on a shared ancestor SHA with an attacker-chosen `description`/`target_url`/`context` (e.g. a misleading CI URL or a script string). GitHub genuinely fires the `status` webhook to Shipit, correctly signed with Repo A's own webhook secret. `verify_signature` passes legitimately — no forged signature, no bypass. `StatusHandler#process` then matches the shared SHA against **Repo B's** `Commit` row (owned by the victim's stack) and writes the attacker's `description`/`target_url`/`context` into a `Status` whose `stack_id` belongs to the victim stack, not the attacker's.

Existing guards do not prevent this: `verify_signature` authenticates *who sent the request*, not *which commit/stack the payload is allowed to affect*; the `ExplicitParameters` schema on `StatusHandler` only validates types/presence, not ownership [6](#0-5) ; there is no `repository.full_name`/`stack.repository` cross-check anywhere in the handler.

### Impact Explanation
The write lands on a victim-owned `Status` row (correct `stack_id`/commit ownership per the victim stack) but with fully attacker-chosen content strings. This `Status` participates in the commit's aggregate CI state (`Status::Group`) and is rendered in Shipit's commit/status UI partials (`app/views/shipit/statuses/_status.html.erb`, `app/views/shipit/statuses/_group.html.erb`) which display `target_url` (as a CI link) and `description`, so a victim's commit can appear to have a legitimate-looking (but attacker-authored) CI result/link. It can also flip `deployable?`/state transitions (`add_status` fires `deployable_status` hooks and can enqueue `ContinuousDeliveryJob`/merge processing) — i.e., attacker-controlled status content can influence whether a victim's commit is treated as deployable, which crosses into "payload for one repository mutating another's stack/commit" (Critical category). This is repeatable against any pair of repositories that share commit history (very common for forks/mirrors, which is the normal Shipit use case) and does not require guessing any secret.

### Likelihood Explanation
Preconditions: the attacker must control (own or have push/API access to) at least one repository that is itself onboarded as a Shipit stack with a working GitHub webhook, and that repository must share at least one commit SHA with a victim stack's tracked repository (true whenever the attacker's repo is a fork, mirror, or shares any git history/ancestor commit with the victim repo — an extremely common scenario). No Shipit or GitHub secret, no privileged Shipit role, and no session/token is required; the attacker only uses their own legitimate GitHub repo permissions (able to hit `POST /repos/:owner/:repo/statuses/:sha`) which GitHub itself signs and forwards. This is directly, repeatably exploitable against any victim stack sharing history with an attacker-controlled repo.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` to the repository that was actually authenticated by `verify_signature` — e.g., join through `Stack`/`Repository` and require `commit.stack.repository.full_name == params.repository_full_name` (or equivalent owner/name match) in addition to `sha`, rejecting/ignoring matches for commits belonging to stacks whose repository does not match the payload's `repository` object.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test ":status from an unrelated repository writes into a victim commit sharing the same sha" do
  victim_stack  = shipit_stacks(:shipit)          # tracks org/victim-repo
  attacker_stack = shipit_stacks(:cyclimse)       # tracks org/attacker-repo (different repository)
  shared_sha = 'deadbeef' * 5

  victim_commit = victim_stack.commits.create!(sha: shared_sha, author: shipit_users(:shipit),
    committer: shipit_users(:shipit), authored_at: Time.now, committed_at: Time.now)

  request.headers['X-Github-Event'] = 'status'
  GithubHook.any_instance.stubs(:verify_signature).returns(true) # simulates a genuinely-signed webhook from attacker's own repo

  body = {
    'sha' => shared_sha,
    'state' => 'success',
    'description' => '<script>alert(1)</script>',
    'target_url' => 'https://evil.example.com/fake-ci',
    'context' => 'ci/attacker',
    'repository' => { 'full_name' => attacker_stack.repository.full_name,
                       'owner' => { 'login' => attacker_stack.repository.owner } }
  }.to_json

  post :create, body:, as: :json

  status = victim_commit.statuses.last
  # Binding check: the Status row belongs to the victim's stack...
  assert_equal victim_stack.id, status.stack_id
  # ...but its content came from the attacker's unrelated repository's webhook body.
  assert_equal '<script>alert(1)</script>', status.description
  assert_equal 'https://evil.example.com/fake-ci', status.target_url
end
```
This demonstrates the equality `Status.stack_id == victim_stack.id` while `Status.description/target_url == attacker-controlled JSON body values`, proving the write is not scoped to the repository that authenticated the request.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-29)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L24-33)
```ruby
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
```
