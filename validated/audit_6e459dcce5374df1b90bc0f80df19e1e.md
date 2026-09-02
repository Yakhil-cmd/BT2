### Title
Cross-repository commit-status forgery via sha-only lookup bypasses `deployable?` for unlocked commits - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves the target `Commit` purely by `sha`, with no check that the webhook's `repository.full_name`/`repository_owner` matches the commit's own stack repository. Combined with `Commit#deployable?`, this lets a status forged for *any* repository the attacker controls (that shares a sha with a victim commit) flip `deployable?` to `true` for an unlocked victim commit, while `locked?` remains the only control that stops the forged status from taking effect.

### Finding Description
The broken binding: `Status#stack_id == Commit#stack_id` is implicitly assumed to always correspond to the repository that originated the webhook, i.e. the code assumes `webhook.repository.full_name == commit.stack.repository.full_name`. That equality is never checked.

Path:
- `Shipit::WebhooksController#verify_signature` only confirms the payload is a legitimately signed webhook for *some* GitHub organization/app matching `repository_owner` in the payload [1](#0-0) . It never binds the event to the specific repository referenced by `params.dig('repository','full_name')` against the stack(s) that will be mutated.
- `StatusHandler#process` looks up ALL `Commit` rows across ALL stacks by `sha` alone and applies the status to each: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [2](#0-1) . There is no filter on `stack.repository` or `github_repo_name`.
- `Status.replicate_from_github!` persists the state keyed only by `stack_id` derived from the (wrongly matched) commit, with no repository-identity validation [3](#0-2) .
- `Commit#deployable?` is `!locked? && (stack.ignore_ci? || (success? && !blocked?))` [4](#0-3) . `locked?` is a plain boolean column set only via the explicit `Commit#lock(user)` action performed by an operator [5](#0-4) .

Exploit flow: an attacker who owns/controls a repository wired into the same Shipit-integrated GitHub App/org can reproduce a victim commit's exact git object (content-addressed sha) in their own repository (trivial for any commit whose tree/parents/timestamps are public, e.g. any open-source PR) and push it, or otherwise trigger a genuine, correctly-signed GitHub `status` webhook for that sha with `state: success`. Because `StatusHandler` matches by `sha` only, this status is attached to the victim `Commit` row in a completely different stack. If that victim commit is **not** locked, `success? && !blocked?` becomes true and `deployable?` flips to `true`, which can trigger `schedule_continuous_delivery` and an autonomous deploy/rollback of the victim stack [6](#0-5) . If the victim commit is `locked?`, `!locked?` short-circuits `deployable?` to `false` regardless of the forged status, correctly containing the attack for that commit only.

Existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema on `StatusHandler`) validate webhook authenticity and payload shape, not repository identity, so they do not prevent this divergence.

### Impact Explanation
The forged status is written into `Status`/via `add_status` for a commit belonging to a stack the attacker does not own, and can make `Commit#deployable?` return `true` for an unlocked commit that has not actually passed CI in its real repository [4](#0-3) . This is a payload from one repository mutating another repository's commit/stack state and can trigger an unauthorized continuous deployment, matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy"). It is repeatable against any stack/commit whose sha the attacker can reproduce, across tenants sharing the Shipit instance/GitHub App. `locked?` is confirmed as the only mitigating control; no repository-identity check exists anywhere in this path.

### Likelihood Explanation
Requires: (1) the attacker's repository shares the same GitHub App/organization webhook configuration as the victim's Shipit instance (so `verify_signature` passes for a real, GitHub-signed event), and (2) the ability to reproduce an identical git commit object (same sha) in a repository they control, which is straightforward for public commits/open-source PRs via `git commit-tree`/cherry-pick with identical metadata. No Shipit secrets, sessions, or maintainer privileges are needed. The victim commit must be unlocked, which is the default state for essentially all commits (locking is a manual, rare operator action).

### Recommendation
In `StatusHandler#process` (and analogously in `CheckRunHandler`/`CommitDeploymentHandler` if similarly affected), scope the `Commit` lookup by the stack's repository, e.g. join through `Stack` and filter by `stack.repository.full_name == params.dig('repository','full_name')` (or `params.name`/`repository_owner`) before applying `create_status_from_github!`, instead of matching by `sha` alone across all stacks.

### Proof of Concept
```ruby
# test/models/commits_test.rb (or a new test file)
test "#deployable? stays false for a locked commit even with a forged cross-repo status" do
  commit = shipit_commits(:first)
  user = shipit_users(:mrkrabs)
  commit.lock(user)
  assert_predicate commit, :locked?

  forged_status = OpenStruct.new(
    state: 'success',
    description: 'forged from attacker repo',
    context: 'ci/forged',
    created_at: Time.now.to_formatted_s(:db)
  )
  commit.create_status_from_github!(forged_status)

  assert_equal false, commit.reload.deployable?
end

test "#deployable? becomes true for an UNLOCKED sibling commit given the same forged status" do
  commit = shipit_commits(:second) # unlocked commit, same-shaped scenario
  refute_predicate commit, :locked?

  forged_status = OpenStruct.new(
    state: 'success',
    description: 'forged from attacker repo',
    context: 'ci/forged',
    created_at: Time.now.to_formatted_s(:db)
  )
  commit.create_status_from_github!(forged_status)

  assert_equal true, commit.reload.deployable?
end
```
These assertions demonstrate the equality `webhook.repository == commit.stack.repository` is never checked: identical forged status content produces divergent, attacker-controlled `deployable?` outcomes based solely on the unrelated `locked` flag.

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

**File:** app/models/shipit/status.rb (L23-34)
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
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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

**File:** app/models/shipit/commit.rb (L338-343)
```ruby
    def lock(user)
      update!(
        locked: true,
        lock_author_id: user.id
      )
    end
```
