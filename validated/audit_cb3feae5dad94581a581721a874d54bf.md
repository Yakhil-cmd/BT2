### Title
Cross-repository Status forgery via unscoped SHA lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit(s) for an incoming GitHub `status` webhook with a global, repository-unscoped query (`Commit.where(sha: params.sha)`), while `WebhooksController#verify_signature` only authenticates that the payload's HMAC matches the webhook_secret of the *sender's* organization (`repository_owner`), not that the affected commit actually belongs to that organization's repository. This lets a legitimate webhook signed by Org A (the attacker's own tenant/repo) create a `Status` row on a `Commit` belonging to Org B's stack, as long as the two commits share a SHA1 value.

### Finding Description
The claimed binding is: `CI provider authorized for victim repo's GitHub App installation == org whose webhook_secret produced the stored Status`. Tracing the code shows this binding is **not enforced**.

- `WebhooksController#verify_signature` derives `repository_owner` from the payload (`params.dig('repository','owner','login')`) and validates the signature against `Shipit.github(organization: repository_owner)`'s `webhook_secret` [1](#0-0) . This only proves the request really came from GitHub for *some* org's App installation — it says nothing about which `Commit`/`Stack` the payload's `sha` should be applied to.
- `StatusHandler#process` then does:
  ```ruby
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
  ``` [2](#0-1) 
  This is a **global, unscoped** ActiveRecord query across every `Commit` row in every `Stack`/repository. Contrast this with `CheckSuiteHandler`, which correctly scopes lookups through the `stacks` helper (`Repository.from_github_repo_name(repository_name).stacks`) before matching commits [3](#0-2)  and [4](#0-3) . `StatusHandler` never uses this `stacks` scoping helper at all.
- `Commit#create_status_from_github!` writes the Status using the *matched commit's own* `stack_id` [5](#0-4)  and `Status.replicate_from_github!` persists state/description/context verbatim from the attacker-controlled payload [6](#0-5) .
- `Commit#status`/`#state` resolves via the status hierarchy (failure/error > pending > success > Unknown), confirmed by the existing test `"#status hierarchy uses failures and errors, then pending, then successes, then Status::Unknown"` [7](#0-6) , so a commit with zero real statuses (`Unknown`) becomes `success` purely from the forged row.
- `Commit#deployable?` is `!locked? && (stack.ignore_ci? || (success? && !blocked?))` [8](#0-7) , so it flips from false to true once the forged `success` Status lands.

**Exploit flow**: The attacker controls a repository under some organization Org A that has the Shipit GitHub App installed (a legitimate Shipit tenant/customer relationship — this is a real precondition, see Likelihood). They construct a commit in their own repo whose SHA1 hash collides with the victim's commit SHA — feasible because SHA1 is fully determined by tree content + author/committer/timestamps/message, all of which are public/known for the victim's real commit (e.g., a public open-source repo). Attacker replicates that exact commit into their own Org A repo (git allows pushing/importing a commit object with identical metadata, producing an identical SHA), then sets a `success` status on it via GitHub's real Status API for their own repo. GitHub genuinely and correctly signs the resulting `status` webhook with Org A's real `webhook_secret` and POSTs it to Shipit. `verify_signature` passes (it is a legitimate signature for Org A). `StatusHandler#process` then matches **any** `Commit` row across the whole database with that SHA — including the victim's commit under an unrelated Org B stack — and stamps a `success` Status onto it, sourced entirely from the attacker's own unrelated repository/CI.

Existing guards do not catch this: `verify_signature` validates org authenticity but not commit-to-repository ownership; `ExplicitParameters` (`StatusHandler.params`) only validates payload shape, not repo binding; there is no `stacks.where(...)` scoping in `StatusHandler` as there is in `CheckSuiteHandler`.

### Impact Explanation
This is an authentication-scope bypass across tenants: a webhook correctly authenticated for repository/org A is used to write a `Status` record for a commit belonging to a completely different repository/stack (org B), with attacker-controlled `state`, `description`, `context`. Because `Commit#deployable?` depends solely on `status.state` (and stack config), a victim commit with zero legitimate CI signal can be flipped to deployable purely by this forged cross-repo Status. This can lead to an unauthorized deploy being triggered (if continuous delivery is enabled) or an operator being misled into manually deploying an unvetted commit — matching the "Critical: unauthorized deploy" impact category. It also generically breaks the CI-gate guarantee for any Shipit stack sharing the SHA1 namespace with any other Shipit-managed repository, i.e., cross-tenant blast radius, not limited to one victim.

### Likelihood Explanation
Preconditions: (1) the attacker must control a repository under some organization that is already a legitimate Shipit tenant with the GitHub App installed (so that a real signed webhook can be produced) — this is not "zero privilege" in the sense of any random internet user, but it is unprivileged with respect to the *victim's* repository/org, matching the threat model (attacker "owns a repo" and can "emit webhooks from a repository they own"). (2) The attacker must be able to reproduce an identical SHA1 for a commit they control vs. the victim's commit, which requires knowing the victim commit's exact tree and metadata (feasible for public repos, and git tooling makes constructing an identical commit object straightforward once the content is known). Given these two conditions, the exploit is fully automatable and repeatable against any victim commit whose content is known, across any pair of Shipit-managed repositories/tenants sharing the platform.

### Recommendation
Scope `StatusHandler#process` (and any other handler that queries `Commit`/`Stack` by attacker-supplied identifiers) to the repository indicated by the authenticated webhook payload, mirroring the `stacks` helper already used by `CheckSuiteHandler`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This ensures a Status can only be attached to a commit belonging to the same repository that GitHub authenticated in the webhook signature, closing the cross-tenant SHA-collision path.

### Proof of Concept
Minitest plan (model/controller level, no live GitHub needed — stub `verify_signature` as existing tests do):
```ruby
test "cross-repo status forgery via unscoped sha lookup" do
  GithubHook.any_instance.stubs(:verify_signature).returns(true)

  victim_repo  = create_repository(owner: 'org-b', name: 'victim-repo')
  victim_stack = create_stack(repository: victim_repo)
  victim_commit = victim_stack.commits.create!(sha: 'deadbeef' * 5, ...) # fresh commit, zero statuses
  refute_predicate victim_commit, :deployable? # pre-attack: Unknown -> not deployable

  attacker_repo = create_repository(owner: 'org-a', name: 'attacker-repo')
  # Forged webhook: signed for org-a, but references victim_commit.sha
  body = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'repository' => { 'full_name' => 'org-a/attacker-repo', 'owner' => { 'login' => 'org-a' } }
  }.to_json

  request.headers['X-Github-Event'] = 'status'
  post :create, body:, as: :json

  victim_commit.reload
  assert_equal 'success', victim_commit.state
  assert_predicate victim_commit, :deployable? # post-attack: forged cross-repo success -> deployable
end
```
Both sides of the binding — `victim_commit.stack.repository` (org-b) vs. the authenticated `repository_owner` (org-a) — differ, yet the Status is still written and `deployable?` flips, proving the binding is broken.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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

**File:** app/models/shipit/status.rb (L23-33)
```ruby
    class << self
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

**File:** test/models/commits_test.rb (L779-803)
```ruby
    test "#status hierarchy uses failures and errors, then pending, then successes, then Status::Unknown" do
      commit = shipit_commits(:first)
      pending = commit.statuses.new(stack_id: @stack.id, state: 'pending', context: 'ci/pending')
      failure = commit.statuses.new(stack_id: @stack.id, state: 'failure', context: 'ci/failure')
      error = commit.statuses.new(stack_id: @stack.id, state: 'error', context: 'ci/error')
      success = commit.statuses.new(stack_id: @stack.id, state: 'success', context: 'ci/success')

      commit.reload.statuses = [pending, failure, success, error]
      assert_equal 'error', commit.status.state

      commit.reload.statuses = [pending, failure, success]
      assert_equal 'failure', commit.status.state

      commit.reload.statuses = [pending, error, success]
      assert_equal 'error', commit.status.state

      commit.reload.statuses = [success, pending]
      assert_equal 'pending', commit.status.state

      commit.reload.statuses = [success]
      assert_equal 'success', commit.status.state

      commit.reload.statuses = []
      assert_equal 'unknown', commit.status.state
    end
```
