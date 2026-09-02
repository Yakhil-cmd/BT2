### Title
Cross-repository Status forgery via unscoped `sha` lookup in `StatusHandler#process` makes `UndeployedCommit#deploy_disallowed?` return false for a foreign, unauthenticated commit - ([File: app/models/shipit/webhooks/handlers/status_handler.rb], [File: app/models/shipit/undeployed_commit.rb])

### Summary
`Webhooks::Handlers::StatusHandler#process` applies an incoming GitHub `status` webhook to **every** `Commit` row sharing the payload's `sha`, with no check that the webhook's originating repository matches the repository owning that commit's stack. Because `UndeployedCommit#deploy_disallowed?` and `Commit#deployable?` trust `commit.status`/`commit.statuses`, any tenant able to trigger a genuinely-signed `status` webhook for their own repository can inject a forged `success` status onto a commit belonging to a completely different stack/tenant whenever a same-sha `Commit` row exists there (e.g. via forks, mirrors, or multiple stacks tracking the same upstream repository).

### Finding Description
The claimed binding — "commit surfaced as `allowed` in `deploy_state`" == "commit whose CI success originates from its own stack's repository" — does **not** hold.

`UndeployedCommit#deploy_disallowed?` and `#deploy_state` rely on `deployable?`/`status`, which are derived from `Commit#statuses` [1](#0-0) . Those `Status` rows are created via:

```
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [2](#0-1) 

This lookup is keyed **only** on `sha`, globally across the `commits` table, with no comparison to the payload's `repository`/`repository_owner` fields against the target commit's `stack.repository`. `create_status_from_github!` then writes the state using the *found commit's own* `stack_id` [3](#0-2) , so the resulting `Status` legitimately attaches to that foreign stack, but its `state`/`context`/`description` are fully attacker-controlled from the webhook body.

Webhook authenticity (`verify_signature`) is checked against the webhook secret associated with `repository_owner` extracted from the *attacker's own payload* [4](#0-3) , i.e. it proves the request came from *some* GitHub repository/org the attacker controls (or is a legitimate tenant of), not that it came from the repository owning the target commit. Nothing in `StatusHandler`'s `ExplicitParameters` schema requires or checks a `repository` field [5](#0-4) , so the repository-identity check is entirely absent from the write path.

Exploit flow: attacker owns/controls a repository whose commit history shares a sha with a victim's tracked commit (trivial via a fork of the victim's public repo, a mirror, or simply another stack/environment tracking the same upstream repository — all producing a `Commit` row with an identical `sha` in the victim's stack). The attacker triggers (or POSTs, if they can produce a validly-signed request for their own tenant) a `status` event with `state: "success"` and that shared `sha`. `StatusHandler` finds and updates the victim's `Commit` row, `Commit#deployable?` becomes true, `UndeployedCommit#deploy_disallowed?` becomes `false`, and `expected_to_be_deployed?` can include the commit in the continuous-deployment queue exposed via `deploy_state`.

### Impact Explanation
A payload originating from one repository/tenant mutates another tenant's commit CI state and forces it into the "allowed"/continuous-deployment path, matching the Critical category "a payload for one repository mutating another's stack, commit, task" and enabling an unauthorized deploy of a false-green commit. This is repeatable against any stack that has a `Commit` row sharing a `sha` with an attacker-reachable repository, and blast radius spans all tenants on a shared Shipit instance sharing the same underlying git history (forks/mirrors/multi-environment stacks of one repo).

### Likelihood Explanation
Exploitation requires the attacker to (a) control a repository whose webhook is genuinely delivered/signed for some tenant on the Shipit instance, and (b) have a target commit whose `sha` also exists in a `Commit` row of a different stack — a common condition for forks, mirrors, or multiple stacks/environments tracking the same repository. No Shipit secrets, sessions, or API tokens are needed; the only requirement is a validly-signed webhook from the attacker's own onboarded repository, which is squarely within the stated unprivileged-attacker capability of "emit webhooks from a repository they own."

### Recommendation
In `StatusHandler#process`, restrict the update to commits whose owning stack's repository matches the webhook's `repository` (owner/name) from the payload, e.g. `Commit.where(sha: params.sha).select { |c| c.stack.repository.full_name == payload_repository_full_name }`, or better, join `Commit -> Stack -> Repository` in the query itself rather than trusting only `sha`.

### Proof of Concept
```ruby
# test/models/undeployed_commit_test.rb (illustrative)
test "a status from a different repository cannot mark a foreign commit deployable" do
  victim_stack = shipit_stacks(:shipit)          # belongs to repo "shopify/shipit-engine"
  attacker_stack = shipit_stacks(:cyclimse)       # belongs to a different repo, e.g. "attacker/other-repo"

  shared_sha = "a" * 40
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "victim", author: shipit_users(:shipit), committer: shipit_users(:shipit), authored_at: Time.now, committed_at: Time.now)
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, message: "attacker", author: shipit_users(:shipit), committer: shipit_users(:shipit), authored_at: Time.now, committed_at: Time.now)

  # Attacker sends a genuinely-signed status webhook for THEIR OWN repo, sha collides with victim's commit
  Shipit::Webhooks::Handlers::StatusHandler.new.call(
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/travis',
    'repository' => { 'full_name' => 'attacker/other-repo', 'owner' => { 'login' => 'attacker' } }
  )

  undeployed = Shipit::UndeployedCommit.new(victim_commit.reload, index: 0)
  assert_equal 'allowed', undeployed.deploy_state
  refute undeployed.deploy_disallowed?
end
```

### Citations

**File:** app/models/shipit/undeployed_commit.rb (L18-41)
```ruby
    def deploy_state(bypass_safeties = false)
      state = deployable? ? 'allowed' : status.state

      unless bypass_safeties
        if blocked?
          state = 'blocked'
        elsif locked?
          state = 'locked'
        elsif stack.active_task?
          state = 'deploying'
        end
      end
      state
    end

    def redeploy_state(bypass_safeties = false)
      state = 'allowed'
      state = 'deploying' if !bypass_safeties && stack.active_task?
      state
    end

    def deploy_disallowed?
      !deployable? || !stack.deployable?
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
