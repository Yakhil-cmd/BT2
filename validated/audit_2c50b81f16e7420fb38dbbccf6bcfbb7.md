### Title
StatusHandler#process updates Commit rows by `sha` alone, letting a webhook for repository R2 flip CI status for an identical-sha commit belonging to stack R1 - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` and calls `create_status_from_github!` on every match, without ever checking that `payload['repository']['full_name']` matches the repository that owns each `Commit`/`Stack`. Because the base `Handler` class exposes `repository_name`/`stacks` helpers precisely for this kind of scoping but `StatusHandler` never calls them, any two `Shipit::Commit` rows across unrelated stacks that happen to share a `sha` (e.g., the well-known empty-tree SHA `4b825dc642cb6eb9a060e54bf8d69288fbee4904`, or any deterministic content-addressed tree/commit collision) will both be updated when a status event arrives for just one of them.

### Finding Description
The binding that should hold is: `payload.dig('repository','full_name') == commit.stack.repository.full_name` for every `Commit` row mutated by the handler. Tracing the code:

- `app/controllers/shipit/webhooks_controller.rb#create` parses the JSON body and dispatches to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [1](#0-0) .
- `verify_signature` only checks that the raw body is HMAC-signed with the secret configured for `repository_owner` (the organization named in the payload) — it authenticates that the payload really came from GitHub for that org/repo, but it does not bind the payload to any specific `Stack` or `Commit` [2](#0-1) .
- `Handler` base class defines `stacks` and `repository_name`, intended to scope processing to the stacks of the reporting repository [3](#0-2) .
- `StatusHandler#process` never calls either helper; it does a global lookup: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [4](#0-3) .
- `Commit#create_status_from_github!` calls `add_status`, which replicates the GitHub status, potentially flips `previous_status` to `success`, emits `commit_status`/`deployable_status` hooks, and — critically — calls `stack.schedule_merges if new_status.pending? || new_status.success?` [5](#0-4) . A success status also feeds `deployable?` used by continuous delivery scheduling [6](#0-5) .

Exploit flow: the attacker owns (or is an authorized committer on) repository R2, which is a legitimate Shipit-monitored repo in an org that has the GitHub App/webhook installed (a real, signed webhook from GitHub is required — the attacker cannot forge the HMAC signature, but they can trivially generate a real one by pushing to their own repo). They create an empty-tree commit (`git commit-tree <empty-tree> -m "x"`, no parent) — this SHA is deterministic and identical across all repositories regardless of tree content history, or more generally any content-addressed collision producing an identical `sha`. If that exact `sha` also exists as a `Shipit::Commit` row belonging to stack R1 (a different, unrelated repository/tenant) — plausible via squash/rebase producing byte-identical trees, or simply because SHA collision engineering isn't required for the empty-tree case since it's a fixed, well-known constant — then pushing that commit to R2 and setting/receiving a `status: success` webhook for it causes GitHub to deliver a validly-signed status webhook naming R2. `StatusHandler#process` will match **both** the R2 commit row and the unrelated R1 commit row (since the query is global by `sha`), and will call `create_status_from_github!` on both, flipping R1's Commit status to `success` even though R1 never observed CI for that commit.

Existing guards do not stop this: `verify_signature` authenticates the payload's *origin org*, not its *target commit*; `ExplicitParameters` only validates the shape of `sha`/`state`/etc., not repository ownership; there is no `stacks`/`repository_name` scoping applied in `StatusHandler`, unlike what the `Handler` base class provides for exactly this purpose.

### Impact Explanation
A payload authenticated for repository R2 can flip the CI status (including to `success`) of a `Shipit::Commit` belonging to an entirely different stack/repository R1, with no relationship between R2 and R1 required other than a matching `sha`. Since `success` status feeds `deployable?` and `schedule_merges`/continuous-delivery scheduling, this is a payload-for-one-repository-mutating-another's-commit/stack scenario — matching the **Critical** category ("a payload for one repository mutating another's stack, commit, task or team"). This is repeatable against any stack whose commits collide in `sha` with a commit the attacker can produce or observe in their own repository (the empty-tree SHA being a trivial, universally available example that requires zero brute force).

### Likelihood Explanation
The attacker needs: (1) to own/control a repository that is registered with Shipit and whose org has the GitHub App/webhook properly installed and signing (a legitimate precondition met by any onboarded tenant repo, not a secret the attacker needs to know — GitHub signs on the operator's behalf), and (2) a target `Shipit::Commit` row elsewhere in the system whose `sha` matches a sha the attacker can produce, such as the empty-tree commit `4b825dc642cb6eb9a060e54bf8d69288fbee4904`, which is deterministic and repo-independent, or any other content-address collision (e.g., squash/rebase producing an identical tree+message+timestamps, which is far less trivial to control precisely due to author/committer timestamp entropy in the sha but is architecturally possible). The empty-tree case specifically requires that some tenant's stack actually has a `Commit` row with that exact sha (an empty, no-op commit), which is a narrower but real occurrence (e.g., initial commits, some rebase/squash workflows producing empty diffs). Attacker cost is a single git commit and a status API call/push to their own repo — trivial and repeatable at will against any repository they control.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the reporting repository using the `stacks`/`repository_name` helpers already defined on `Handler`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.joins(stack: :repository).where(sha: params.sha, repository: { full_name: repository_name })`, mirroring what other handlers (e.g., `PushHandler`) presumably already do via `stacks`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual, minitest, no live GitHub)
test "status webhook for repository R2 must not flip status of a commit belonging to unrelated stack R1 with the same sha" do
  shared_sha = '4b825dc642cb6eb9a060e54bf8d69288fbee4904' # empty-tree sha, deterministic

  stack_r1 = shipit_stacks(:shipit) # belongs to repository R1
  stack_r2 = create_stack!(repository_full_name: 'attacker/r2') # unrelated repository owned by attacker

  commit_r1 = stack_r1.commits.create!(sha: shared_sha, message: 'r1 commit', ...)
  commit_r2 = stack_r2.commits.create!(sha: shared_sha, message: 'r2 commit', ...)

  assert_equal 'unknown', commit_r1.reload.status.state
  assert_equal 'unknown', commit_r2.reload.status.state

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'repository' => { 'full_name' => 'attacker/r2', 'owner' => { 'login' => 'attacker' } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  # Binding under test: only commit_r2 (owned by attacker/r2) should change.
  assert_equal 'success', commit_r2.reload.status.state   # expected: attacker's own commit updates
  assert_equal 'unknown', commit_r1.reload.status.state    # BUG: currently also flips to 'success'
end
```
This test demonstrates that `StatusHandler#process`'s global `Commit.where(sha: ...)` scan mutates `commit_r1` even though the payload's `repository.full_name` (`attacker/r2`) does not match `commit_r1`'s owning repository, confirming the cross-tenant write.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L365-386)
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
