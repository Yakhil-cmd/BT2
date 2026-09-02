### Title
Cross-tenant CI status forgery via sha-only lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits solely by `sha` across the entire `Commit` table, with no scoping to the repository that authenticated the webhook, unlike every other handler (e.g. `PushHandler`) which scopes through `stacks`. Any org member who can produce a commit with the same sha as a victim stack's head commit can attach an arbitrary CI `Status` (including `success`) to that victim's `Commit` row, letting them flip `Commit#deployable?` for a stack they do not own.

### Finding Description
The broken binding: the `Status#stack_id` written must equal a `stack_id` that belongs to the webhook-verified `repository.full_name`. In code:

- `Handler#stacks` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) correctly scopes lookups to `Repository.from_github_repo_name(repository_name)&.stacks`, and `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) uses this scope (`stacks.not_archived.where(branch:)`).
- `StatusHandler#process` does **not** use `stacks` at all:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

This queries `Commit` globally by `sha`, with no `stack_id`/`repository_id` filter tying the result to the repository named in `payload['repository']['full_name']`.

- `Commit#create_status_from_github!` then calls `statuses.replicate_from_github!(stack_id, github_status)` [2](#0-1) , and `Status.replicate_from_github!` writes `stack_id: stack_id` taken from whatever commit was matched by sha [3](#0-2) .

`WebhooksController#verify_signature` only checks that the payload is a validly signed webhook for `repository_owner` (the GitHub organization) using that org's configured `webhook_secret` [4](#0-3) . It does not, and cannot, verify that the specific `sha`/commit inside the payload actually belongs to the `repository.full_name` claimed — that check is left entirely to each handler's own scoping, which `StatusHandler` omits.

**Exploit path:** an attacker who has write/webhook access to *any* repository under the same GitHub organization that Shipit is already configured for (an org member with their own repo, not a Shipit operator or repository maintainer of the victim's repo) can:
1. Obtain a commit whose sha collides with the victim stack's head commit sha. Since git shas are content-addressed, this is trivially achieved if the attacker forks/mirrors the victim's (or any shared-history) repository into their own repo — the sha is identical byte-for-byte, no cryptographic collision needed.
2. Configure/trigger a `status` webhook from their own repository with that sha and `state: success` (this is a legitimate GitHub webhook from the attacker's own repo, correctly signed by the org's secret they never had to know — GitHub sends it).
3. `StatusHandler#process` finds `Commit.where(sha: victim_sha)`, which returns the victim stack's commit (not any commit belonging to the attacker's repo/stacks), and creates a `Status` row with the victim's `stack_id` and `state: 'success'`.
4. If the victim stack has no `blocking_statuses` configured (`stack.blocking_statuses.empty?` → `Commit#blocked?` short-circuits to `false` at `app/models/shipit/commit.rb:231-232`), then `Commit#deployable?` = `!locked? && (ignore_ci? || (success? && !blocked?))` becomes true purely from the forged status, with no real CI ever run for that stack [5](#0-4) .

None of the standard guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema) prevent this, because they operate at the "is this a valid webhook for this org" layer, not at the "does this sha belong to the claiming repository" layer — that binding is simply never checked in `StatusHandler`.

### Impact Explanation
This allows a payload from one repository to mutate another repository's `Stack`'s deployability state — a cross-tenant record write matching the "Critical: payload for one repository mutating another's stack/commit" category. Concretely, an attacker can make a victim stack's commit appear `success?` and thus `deployable?`, enabling an unauthorized deploy if continuous deployment or manual deploy triggers depend on that state (`Status#schedule_continuous_delivery` in `app/models/shipit/status.rb:19,42-44` schedules CD directly from the forged status). This is repeatable against any stack in the same GitHub organization for which the attacker can produce (via forking/mirroring) a matching commit sha.

### Likelihood Explanation
Requires: attacker controls a repository under the same GitHub org already configured in Shipit with a valid GitHub App/webhook secret (a normal, low-privilege scenario in multi-repo/multi-team orgs); the victim stack has `blocking_statuses` empty (a common default) and an unlocked commit. Obtaining a matching sha is straightforward via forking or mirroring public/shared-history repos within the org — no brute-force or hash collision needed. Attacker cost is low (push access to their own repo + ability to set a commit status via the GitHub API on their own repo), and the attack is repeatable per-request/per-stack.

### Recommendation
Scope `StatusHandler#process` like `PushHandler` does: restrict the `Commit` lookup to commits belonging to `stacks` derived from the webhook-verified `repository.full_name` (e.g. `Commit.where(sha: params.sha, stack_id: stacks.select(:id))` or iterate `stacks.flat_map { |s| s.commits.where(sha: params.sha) }`) before calling `create_status_from_github!`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, hypothetical — file doesn't currently exist per search):
```ruby
test "process does not create a Status for a commit belonging to another repository's stack" do
  victim_stack = shipit_stacks(:shipit) # repo "shopify/shipit-engine"
  victim_commit = shipit_commits(:first) # sha shared/duplicated for the test
  attacker_repo_full_name = "shopify/some-other-repo" # different repo, same org

  params = ExplicitParameters::Parameters.new(
    sha: victim_commit.sha, state: 'success'
  )
  handler = Shipit::Webhooks::Handlers::StatusHandler.new(
    { 'repository' => { 'full_name' => attacker_repo_full_name },
      'sha' => victim_commit.sha, 'state' => 'success' }
  )

  assert_no_difference -> { victim_commit.statuses.count } do
    handler.process
  end

  # Equality check: Status#stack_id must equal a stack_id belonging to attacker_repo_full_name's stacks,
  # never victim_stack.id
  refute Shipit::Status.where(commit_id: victim_commit.id, state: 'success').exists?
end
```
This test would currently **fail** (i.e., demonstrate the vulnerability) against the existing `StatusHandler#process` implementation, since it performs `Commit.where(sha: params.sha)` without any repository/stack scoping [1](#0-0) .

### Citations

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
