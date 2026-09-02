### Title
Cross-repository commit-status forgery via unscoped `Commit.where(sha:)` in `StatusHandler#process` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits purely by `sha`, with **no repository or stack scoping at all**, unlike the base `Handler` class's `stacks`/`repository_name` helpers used elsewhere. An attacker who controls a repository whose `status` webhook is verified (signed) for its own organization can craft a commit with a SHA1 that collides with a commit belonging to a completely unrelated stack, and have GitHub emit a signed status payload that Shipit will apply to that unrelated commit.

### Finding Description
The broken binding is: `payload.dig('repository','full_name')` (the org/repo the signature authenticates) must equal `commit.stack.repository.full_name` for every `Commit` mutated by the handler. This equality is **never checked**.

- `Handler#stacks`/`Handler#repository_name` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) implement exactly this scoping (`Repository.from_github_repo_name(repository_name)&.stacks`) and are used by other handlers. [1](#0-0) 
- `StatusHandler#process` bypasses this entirely:
```
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 
It never calls `self.repository_name`, never filters by `stack`, and never cross-checks `commit.stack.repository.full_name` against `payload.dig('repository','full_name')`.

- `WebhooksController#verify_signature` only authenticates that the payload was signed with the webhook secret configured for `repository_owner` (`params.dig('repository','owner','login')`) — it authenticates the *sender org*, not that the `sha` inside the payload actually belongs to that org's repository. [3](#0-2) 

- `Commit#create_status_from_github!` writes a `Status` record for the target commit unconditionally, using attacker-controlled `state`, `description`, `target_url`, `context` fields from `params`, and triggers deployability side effects (`add_status` → `Hook.emit`, `stack.schedule_merges` when state becomes `success`/`pending`). [4](#0-3) [5](#0-4) 

**Exploit flow:** Since a Git commit SHA1 is derived purely from tree/parent/message/author-committer metadata (not the hosting repository), an attacker who can read a target commit's metadata (public on GitHub) can recreate an identical commit object inside their own repository, producing an identical SHA. The attacker then triggers a `status` event on their own repo (e.g., via a CI integration they control) with `state: success`, `context: <required-check-name>`. GitHub signs and delivers this webhook using the webhook secret configured for the attacker's own org — which passes `verify_signature` because that check only validates the sender org, not the `sha`'s true owner. `StatusHandler#process` then finds **all** `Commit` rows across **all** stacks/repositories sharing that SHA (including the victim's), and calls `create_status_from_github!` on each, writing an attacker-controlled status onto the victim commit. If that forged status satisfies `stack.required_statuses`/`blocking_statuses`, it can make `commit.deployable?` true (`success? && !blocked?`) and trigger `schedule_continuous_delivery`, resulting in an unauthorized deploy of the victim's stack.

None of the listed guards intervene: `verify_signature` only checks organization-level HMAC, `drop_unhandled_event` only checks the event type exists, `ExplicitParameters` only validates payload shape (`sha`, `state`, etc.), and there is no model validation binding a `Status`/`Commit` to the webhook's claimed repository.

### Impact Explanation
An attacker who administers/controls a distinct GitHub repository (with a status-emitting integration) can write forged CI-status records onto commits belonging to an entirely unrelated Shipit stack/repository, without ever authenticating against that repository. This is a payload for one repository mutating another repository's stack/commit data, and can escalate to triggering an unauthorized/unintended deploy via `stack.schedule_merges`/continuous delivery if the forged status satisfies required checks — matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy"). The attack is repeatable against any commit whose SHA the attacker can reproduce (any commit with metadata the attacker can read, e.g. via public GitHub, or via committing identical content/metadata).

### Likelihood Explanation
Preconditions: the attacker needs a GitHub repository (their own, e.g. a personal fork/org) that is onboarded to Shipit's `Shipit.github_teams`/organizations configuration sufficiently for `verify_signature` to succeed for that org (i.e., a `webhook_secret` configured for that org, and a status-emitting hook GitHub will fire, e.g. via a CI app the attacker installs on their own repo). No Shipit session, API token, or GitHub secret is required — GitHub itself computes the signature. Reproducing a target SHA requires recreating identical commit metadata (tree, parent, author/committer, timestamps, message) in the attacker's repo, which is feasible for any commit whose metadata is publicly visible (e.g. via GitHub UI/API) and does not require access to the source repo. This is a moderate-cost but fully feasible and repeatable attack against any Shipit deployment where the `status` webhook is wired up.

### Recommendation
Scope `StatusHandler#process` by repository, mirroring the base `Handler#stacks` pattern:
```
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
i.e., resolve `Repository.from_github_repo_name(repository_name)` from the verified payload and restrict the `Commit` lookup to that repository's stacks, so a commit is only mutated when `commit.stack.repository.full_name == payload.dig('repository','full_name')`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual, not to be placed under test/ per rules, illustrative only)
test "process does not scope commits by repository and mutates foreign stack's commit" do
  victim_repo  = shipit_repositories(:shipit)           # unrelated repo/stack
  attacker_full_name = 'attacker/attacker-repo'
  shared_sha = 'deadbeef' * 5

  victim_commit = victim_repo.stacks.first.commits.create!(sha: shared_sha, ...)

  payload = {
    'repository' => { 'full_name' => attacker_full_name },
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/required-check'
  }

  handler = Shipit::Webhooks::Handlers::StatusHandler.new(payload)

  # Spy: repository_name/stacks (inherited, private) should be invoked if scoping existed
  handler.expects(:repository_name).never

  assert_not_equal attacker_full_name, victim_commit.stack.repository.full_name
  handler.process
  victim_commit.reload

  # Vulnerability: victim commit received attacker-controlled status despite
  # payload's repository.full_name != victim_commit.stack.repository.full_name
  assert_equal 'success', victim_commit.status.state
end
```
This demonstrates `repository_name` is never called and that a commit belonging to a stack whose `repository.full_name` differs from `payload.dig('repository','full_name')` is mutated by `StatusHandler#process`.

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
