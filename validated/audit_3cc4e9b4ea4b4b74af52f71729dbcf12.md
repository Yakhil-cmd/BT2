### Title
`StatusHandler#process` matches commits by SHA alone, letting a signed webhook from an attacker-controlled repository write attacker-supplied CI content into another stack's `Status` row - ([File: app/models/shipit/webhooks/handlers/status_handler.rb], [File: app/models/shipit/commit.rb])

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)`, with no filter on the payload's `repository.full_name` against the commit's own stack/repository. `Commit#create_status_from_github!` then calls `statuses.replicate_from_github!(stack_id, github_status)`, which persists the record's own `stack_id` but content taken entirely from the attacker's payload (`state`, `description`, `target_url`, `context`, `created_at`).

### Finding Description
The binding that should hold is: `payload.dig('repository', 'full_name') == commit.stack.repository.full_name` for every `Status` created as a side effect of a webhook. This binding is never checked.

- `Handler` (the base class) exposes a `stacks` helper that scopes by `Repository.from_github_repo_name(repository_name)` [1](#0-0) , but `StatusHandler#process` does not use it at all:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 
- This queries `Commit` globally by `sha` regardless of which repository/stack the matching row belongs to. Since `sha` is not a globally unique key across stacks (different `Stack`/`Repository` rows can hold commits with identical SHAs, e.g. shared ancestor history between an upstream repo and any fork of it), a commit belonging to victim stack `S1` can be matched by a webhook whose `repository` field names a completely different repo.
- `Commit#create_status_from_github!` then writes `stack_id: stack_id` (`S1`, the matched commit's own stack) while every content field (`state`, `description`, `target_url`, `context`, `created_at`) comes straight from the attacker-controlled `params`:
```ruby
def create_status_from_github!(github_status)
  add_status do
    statuses.replicate_from_github!(stack_id, github_status)
  end
end
``` [3](#0-2) 
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
``` [4](#0-3) 

Existing guards do not close this gap:
- `verify_signature` in `WebhooksController` validates the signature using `Shipit.github(organization: repository_owner)`, keyed off `params.dig('repository','owner','login')` from the *attacker's own payload* [5](#0-4) . This confirms the webhook genuinely originated from GitHub for the attacker's own organization/repository (e.g. a GitHub App the attacker installed on their own fork), but it says nothing about which Shipit stack the payload is allowed to mutate — it authenticates the sender's organization, not the target stack.
- `ExplicitParameters` schema on `StatusHandler` only validates types/presence of `sha`, `state`, `description`, `target_url`, `context`, `created_at`, `branches` [6](#0-5)  — no repository-consistency check.
- `drop_unhandled_event` only checks that an event type has a registered handler [7](#0-6) , it does not scope by repository either.

Attacker's exact request: fork a public upstream repo that already has commits ingested into a victim Shipit stack `S1` (forks share identical commit SHAs for shared history). Install/own a GitHub App/webhook config for the fork (any repo owner can do this) so GitHub emits a genuinely-signed `status` event to Shipit's `/webhooks` endpoint, with `sha` equal to one of the shared ancestor commits and `state`/`description`/`target_url`/`context` set to arbitrary attacker-chosen values. The webhook signature verifies (it's a real, GitHub-signed payload for the attacker's own org/repo), `drop_unhandled_event` passes (status handler is registered), and `StatusHandler#process` matches the victim's commit purely by `sha`, writing the forged content against `S1`.

### Impact Explanation
The attacker can inject arbitrary CI status content (`state`, `description`, `target_url`, `context`) that gets stored against a commit belonging to a stack (`S1`) they never authenticated for, and that content becomes visible in the victim stack's UI and can drive `deployable_status`/`commit_status` webhook events, `enable_ci_on_stack`, and continuous-delivery scheduling logic tied to that commit's status. This is a payload for one repository mutating another repository's/stack's data, matching the Critical severity bucket "a payload for one repository mutating another's stack, commit, task or team." It is repeatable against any shared-history commit and any victim stack that happens to share ancestry with a repo the attacker controls.

### Likelihood Explanation
Preconditions: the victim stack must contain commits whose SHAs are shared with a repository the attacker controls (very common for forks of open-source projects, which is the primary use case Shipit targets), and the attacker must be able to get GitHub to emit a real, signed `status` webhook for their own repo (trivial: install a GitHub App/webhook on their own fork and call the GitHub Status API on their own token, or configure a CI job on the fork to post statuses). No Shipit secrets, sessions, or privileged roles are required — only ordinary control over their own repository. This makes the attack low-cost and repeatable.

### Recommendation
In `StatusHandler#process`, use the existing repository-scoping helper (`stacks`) instead of unscoped `Commit.where(sha:)`, e.g. resolve commits only within `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently join through `Repository.from_github_repo_name(payload's repository full_name)` before matching by `sha`, ensuring a `Status` is only ever created for a commit whose stack's repository matches the payload's repository.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status webhook from a different repository cannot forge a status for another stack's commit with a colliding sha" do
  victim_stack = shipit_stacks(:shipit) # repository e.g. "shopify/shipit-engine"
  shared_sha = "abc123deadbeef"
  victim_commit = victim_stack.commits.create!(sha: shared_sha, author: shipit_users(:walrus), committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now, message: "shared ancestor")

  attacker_payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'description' => 'FORGED: totally fine, ship it',
    'target_url' => 'http://attacker.example.com/fake-ci',
    'context' => 'attacker/ci',
    'repository' => { 'full_name' => 'attacker/unrelated-fork', 'owner' => { 'login' => 'attacker' } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)

  status = victim_commit.reload.statuses.last
  # Binding under test: content_authorized_by(status.stack_id) should equal
  # content_originated_from(attacker_payload's repository), but instead:
  assert_equal victim_stack.id, status.stack_id
  assert_equal 'FORGED: totally fine, ship it', status.description
  assert_equal 'http://attacker.example.com/fake-ci', status.target_url
  assert_equal 'attacker/ci', status.context
  # proving payload for "attacker/unrelated-fork" mutated victim_stack's commit status
end
```

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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
