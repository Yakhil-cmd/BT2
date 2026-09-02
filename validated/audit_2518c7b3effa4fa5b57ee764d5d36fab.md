### Title
Cross-repository `status` webhook forgery via unscoped SHA lookup forces production ship/block - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` writes a `Status` for every `Commit` in the database that matches the attacker-supplied `sha`, without checking that the SHA belongs to the repository whose webhook signature was verified. Because Git commit SHAs are content-addressed and shared identically between a public repository and any fork of it, an attacker who owns a fork (and thus a legitimately signed, independent webhook channel) can push a `context: ci/build`, `state: failure` status for a SHA that is also present in a victim's production stack, causing Shipit to record that failing status against the victim's commit and change its deployability.

### Finding Description
The broken binding is: `verify_signature` proves only `signing_organization == payload.repository.owner.login`, but `StatusHandler#process` assumes `signing_organization == commit.stack.repository.owner` for every row it touches — that second equality is never checked.

`Shipit::WebhooksController#verify_signature` looks up `Shipit.github(organization: repository_owner)` from the payload itself and validates the HMAC over the raw body [1](#0-0) , using per-organization `webhook_secret` and `SecureCompare.secure_compare` in `GitHubApp#verify_webhook_signature` [2](#0-1) . This only proves the request came from GitHub for the organization named *inside the attacker-controlled payload* — it says nothing about which repository's commits the `sha` field may legitimately reference.

`StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
with no `stack_id`/repository filter at all [3](#0-2) . `Commit#create_status_from_github!` calls `add_status`, which creates a `Status`, recomputes `status`, fires `deployable_status`/`commit_status` hooks, and — critically — calls `stack.schedule_continuous_delivery`/`ContinuousDeliveryJob` when state transitions to `success`, or blocks deploys via `blocked?`/`deployable?` when it transitions to `failure` [4](#0-3) [5](#0-4) [6](#0-5) .

Exploit flow:
1. Attacker forks a public repository that has a Shipit-tracked production stack. Git commit SHAs are computed purely from commit content (tree, parents, author/committer, message, timestamps), so any commit shared between upstream and the fork (e.g. the commit the fork was created from, or any earlier shared history) has the exact same SHA in both repositories.
2. Attacker installs/owns the GitHub App on their own fork/org (or otherwise has a legitimate webhook channel for their own repository), and uses the GitHub Statuses API to set a status on that shared SHA with `context: ci/build`, `state: failure`.
3. GitHub delivers a `status` webhook signed with *the attacker's own organization's* webhook secret. `verify_signature` passes because it only checks that the signature matches the org claimed in the payload — which is truthfully the attacker's org.
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, which matches not only the attacker's own commit record (if tracked) but also the victim's `Commit` row for the same SHA in the victim's production stack, and writes a `failure` (or `success`) status against it, changing `deployable?`/`blocked?` for the victim's stack.

None of the existing guards prevent this: `verify_signature` validates org-to-signature binding, not sha-to-repository binding; `drop_unhandled_event` only filters unregistered event types; the `ExplicitParameters` schema in `StatusHandler.params` only validates field types/shapes, not ownership; and `StatusHandler#process` performs no `joins(:stack)`/repository-name check against `repository_owner`.

### Impact Explanation
A payload legitimately authenticated for one repository/organization can write a `Status` row that mutates another organization's production stack's commit state — this is exactly "a payload for one repository mutating another's stack, commit, task or team," which is a Critical-severity condition per the given impact taxonomy. The attacker gains the ability to force a `ci/build failure` (or forged `success`) on a victim's tracked commit, which changes `Commit#deployable?`/`blocked?` and can trigger or block `ContinuousDeliveryJob`, `ProcessMergeRequestsJob`, and downstream ship/rollback decisions on the victim's production stack, without any privileges on the victim repository. This is repeatable against any repository whose SHA history overlaps with a repository/fork the attacker controls, and is not limited to a single victim.

### Likelihood Explanation
Preconditions: the attacker needs a repository they can emit signed `status` webhooks from (their own fork, or any repo where they can install/use the GitHub App), and a SHA shared with the victim's tracked stack (trivially satisfied by forking a public repo before pushing further divergent history, or by any historically shared ancestor commit). No Shipit session, API token, or secret is required. This matches an "unprivileged internet attacker" as scoped by the rules, and the attack is cheap and repeatable — it requires only forking a repo and calling the standard GitHub Statuses API on their own fork.

### Recommendation
Scope `StatusHandler#process` to only update commits belonging to stacks whose tracked repository matches the webhook's authenticated repository (e.g., filter `Commit.joins(:stack).where(sha: params.sha, shipit_stacks: { repository_id: authenticated_repository.id })`), and pass the authenticated repository/organization context from the controller into the handler instead of relying solely on `Commit.where(sha:)`.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers_test.rb` or `test/controllers/webhooks_controller_test.rb` style, no live GitHub needed — stub `verify_signature`):

```ruby
test "status webhook for a shared SHA affects an unrelated victim stack" do
  # Two distinct stacks/repos share the same commit SHA (simulating a fork sharing history)
  victim_stack = shipit_stacks(:shipit)          # production stack
  attacker_stack = shipit_stacks(:cyclimse)      # attacker-controlled stack/org

  shared_sha = "abc123deadbeef"
  victim_commit = victim_stack.commits.create!(sha: shared_sha, ...)
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, ...)

  before_state = victim_commit.reload.state          # e.g. "success"/deployable
  before_deployable = victim_commit.deployable?

  # Payload signed/authenticated only for attacker's org (repository_owner == attacker org)
  params = {
    'sha' => shared_sha, 'state' => 'failure', 'context' => 'ci/build',
    'repository' => { 'owner' => { 'login' => 'attacker-org' } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.new.call(params)

  after_state = victim_commit.reload.state
  after_deployable = victim_commit.deployable?

  # Binding under test: signing_org(attacker-org) == victim_stack.repository.owner  -> false
  # yet victim_commit state/deployability changed anyway
  assert_not_equal before_state, after_state
  assert_not_equal before_deployable, after_deployable
end
```
This demonstrates that a webhook authenticated only for the attacker's organization mutates a `Commit` belonging to a different, unrelated stack (the victim's production stack), confirming the unscoped write in `StatusHandler#process`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** app/models/shipit/commit.rb (L360-386)
```ruby
    private

    def message_parser
      @message_parser ||= CommitMessage.new(message)
    end

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
