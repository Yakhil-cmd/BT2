### Title
Cross-repository status webhook pollutes victim `MergeRequest` head commit status - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits solely by `sha` (`Commit.where(sha: params.sha)`) with no check that the webhook's `repository` matches the commit's owning `stack.github_repo_name`. Because git commit SHAs are content-addressed and identical across forks/mirrors of the same history, an attacker who forks a victim's public repository and posts a `status` event on their own fork (a legitimately signed webhook from the attacker's own GitHub App/org) can inject a `success` status onto a `Commit` row belonging to a completely different tenant's stack, causing `MergeRequest#all_status_checks_passed?` to pass and an unauthorized `merge_pull_request` call to fire.

### Finding Description
The broken binding is: `payload.dig('repository', 'full_name')` (attacker's own repo) `!= commit.stack.github_repo_name` (victim's repo), and this inequality is never checked before the status is attached.

- `WebhooksController#verify_signature` selects the GitHub App config to verify against using `repository_owner` from the payload [1](#0-0) . This only proves the webhook was legitimately sent by *some* configured org/app — it says nothing about which `stack`/`Commit` the event is allowed to touch.
- `Handler` provides a `stacks`/`repository_name` helper intended to scope webhook effects to the repository named in the payload [2](#0-1) , but `StatusHandler#process` does not use it. Instead it does a raw, unscoped lookup: [3](#0-2) 
- `Commit.where(sha: params.sha)` matches by `sha` alone across *all* stacks/repos in the database. `create_status_from_github!` then attaches the forged status to whatever commit rows share that SHA [4](#0-3) , and `add_status` triggers `stack.schedule_merges` for the victim's stack [5](#0-4) .
- `MergeRequest#all_status_checks_passed?` builds its check purely from `head.statuses_and_check_runs`, with no repository provenance check on individual statuses [6](#0-5) . If it now includes the forged `success` status, `merge!` proceeds to call `stack.github_api.merge_pull_request` using the victim's stored credentials [7](#0-6) .

Exploit flow: attacker forks victim's public repo (preserving identical commit SHAs for existing history), creates a `status` event with `state: success` on that shared SHA from their own fork/org (a genuinely, validly signed webhook using the attacker's own app credentials/secret), and sends it to `POST /webhooks`. `verify_signature` passes because it's a real, correctly-signed webhook from a legitimate (attacker-controlled) source — it just checks the wrong binding (signer authenticity) instead of the necessary one (repository ownership of the target commit). `StatusHandler#process` then finds the victim's `Commit` (matched purely by SHA) and attaches the forged status to it, regardless of the payload's actual `repository`.

### Impact Explanation
This allows an unauthorized `merge_pull_request` call against a victim repository, using the victim's own stored `GITHUB_TOKEN`/GitHub App credentials, triggered entirely by a webhook whose `repository` field never matches the target stack. This matches the "Critical" impact category: a payload for one repository mutating another's stack/commit, and an unauthorized merge. It's repeatable against any victim stack with an open `pending` `MergeRequest` whose head SHA the attacker can reproduce by forking the (necessarily public, or otherwise accessible) source history, and works cross-tenant against any Shipit instance hosting multiple stacks/orgs sharing the same webhook endpoint.

### Likelihood Explanation
Preconditions: victim stack has an open `pending` `MergeRequest` (visible via the Shipit UI/API or GitHub PR); the head commit SHA is public (visible on GitHub); the attacker must be able to fork the repository (or otherwise produce a commit with an identical SHA) and must have — or be able to create — their own GitHub App/org registered as a `Shipit.github` config to obtain a validly signed webhook. The attacker needs no Shipit credentials and no knowledge of any Shipit secret; they only need their own legitimate GitHub webhook signing setup and read access to the victim's public commit SHA. This is a low-cost, feasible, and repeatable attack against any stack using a shared multi-repo Shipit deployment.

### Recommendation
In `StatusHandler#process` (and similarly for check-run/other SHA-keyed handlers), scope the `Commit` lookup by the repository named in the verified payload — e.g., restrict to `stacks` (via `Repository.from_github_repo_name(repository_name)`) or explicitly assert `commit.stack.github_repo_name == repository_name` before calling `create_status_from_github!`, rejecting/ignoring commits whose owning stack's repo doesn't match the webhook's `repository.full_name`.

### Proof of Concept
minitest outline (no live GitHub calls):
1. Create two stacks: `stack_victim` (`github_repo_name` = `"victim-org/repo"`) and use a commit SHA `sha_shared`.
2. Create `commit = Commit.create!(stack: stack_victim, sha: sha_shared, ...)` and `merge_request = MergeRequest.create!(stack: stack_victim, head: commit, merge_status: 'pending', ...)`, with `commit` currently having no successful status (so `all_status_checks_passed?` is false and `ci_missing`/`ci_failing` would apply).
3. Build a webhook payload: `{ 'sha' => sha_shared, 'state' => 'success', 'context' => 'ci', 'repository' => { 'full_name' => 'attacker-org/other-repo', 'owner' => { 'login' => 'attacker-org' } } }`.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly (bypassing signature verification, since that's a separate, already-passing check in this scenario).
5. Assert: `commit.reload.statuses_and_check_runs.map(&:state)` now includes `'success'` even though `payload.dig('repository','full_name') != stack_victim.github_repo_name`.
6. Assert: `merge_request.reload.all_status_checks_passed?` is now `true`.
7. Stub `Shipit.github.api.expects(:merge_pull_request).with(stack_victim.github_repo_name, merge_request.number, any_parameters)` and run `ProcessMergeRequestsJob.perform_now(stack_victim)` (or `merge_request.merge!` directly), asserting the mock is invoked — demonstrating an unauthorized merge triggered by a foreign-repository status webhook.

### Citations

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

**File:** app/models/shipit/merge_request.rb (L164-176)
```ruby
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
```

**File:** app/models/shipit/merge_request.rb (L193-197)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end
```
