### Title
Cross-repository status forgery unblocks another stack's deploy gate via unscoped `Commit.where(sha:)` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target commit(s) for an incoming GitHub `status` webhook purely by SHA, with no filter on the repository/stack the webhook actually originated from. Any commit sharing that SHA in any stack — including one belonging to a different, unrelated repository — receives the forged status, letting an attacker satisfy another stack's `blocking_statuses` gate and unblock its deploy pipeline.

### Finding Description
The broken binding is: **`webhook.repository.full_name` (the repo the signed event came from) MUST equal `commit.stack.repository.full_name` (the repo of the commit being mutated)**. The code never establishes this equality.

`StatusHandler#process` does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

`Commit.where(sha: params.sha)` queries across the entire `commits` table with no `stack_id`/repository scoping, and the handler's declared params schema does not even require or read a `repository` field: [2](#0-1) 

`create_status_from_github!` then writes the status using the *matched commit's own* `stack_id`, not anything derived from the webhook payload: [3](#0-2) 

This status feeds `Status::Common#blocking?`, which is checked by `Commit#blocked?`: [4](#0-3) [5](#0-4) 

`WebhooksController#verify_signature` only proves the request is a genuinely GitHub-signed webhook for *some* organization (`Shipit.github(organization: repository_owner)`); it never checks that the named `repository` matches the stack that owns the commit being mutated: [6](#0-5) 

Because GitHub App webhook secrets are configured per-organization (not per-repository), any repository within an organization where Shipit's GitHub App is installed shares the same signing secret. An attacker who can create/administer *any* repository in that org (e.g., a new repo they push arbitrary git history into, deliberately re-using commit SHAs copied from the victim's tracked repository) can register a webhook to the Shipit host pointing at their own repo. GitHub will sign that webhook with the org-wide secret, satisfying `verify_signature`, while the payload's SHA collides with a commit that actually belongs to `victim`'s stack. `StatusHandler#process` then attaches a `success` status for `context: 'ci/required'` to the shared-SHA `Commit` row inside `victim`'s stack, satisfying `blocking_statuses` and flipping `blocked?` to `false` for later commits, and `deployable?` to `true`.

None of the existing guards catch this: `verify_signature` validates only "this is truly from GitHub for org X," not "commit X.sha belongs to repository X"; `ExplicitParameters` schema for `StatusHandler` doesn't require/validate `repository`; there is no `require_permission!`/`stacks` scope check in webhook handlers since webhooks are inherently repo-scoped by design assumption — an assumption this handler violates by looking up commits SHA-globally instead of `stack.commits.where(sha:)`.

### Impact Explanation
A payload legitimately signed for one repository/org mutates commit/status state belonging to a stack for a *different* repository, letting an attacker clear a `blocking_statuses` gate they do not control and cause `deployable?`/`schedule_continuous_delivery` to trigger an unauthorized deploy of `victim`'s stack. This matches the Critical category "a payload for one repository mutating another's stack, commit ... or an unauthorized deploy." The attack is repeatable against any stack whose commits share a SHA reachable by an attacker-controlled repository (most easily achieved by copying/forking git history into a repo the attacker administers within an org where Shipit's app is installed).

### Likelihood Explanation
Requires: (1) an organization where the Shipit GitHub App is installed org-wide (so the webhook signing secret is shared across repos), (2) attacker ability to create/administer a repository in that org and push git history containing a commit whose SHA matches one in `victim`'s tracked repository, and (3) that shared commit currently sits in the "blocking" window (undeployed ancestor with a missing/blocking context). These preconditions are plausible in organizations that install the Shipit app at the org level and allow members to create repositories, which is a common configuration; no Shipit secrets, tokens, or privileged roles are needed by the attacker.

### Recommendation
Scope commit lookup in `StatusHandler#process` (and any other SHA-keyed webhook handler) to the repository named in the webhook payload, e.g. resolve `Stack`/`Repository` from `params.dig('repository','full_name')` first, then only update `commit.stack_id` records whose `stack.repository` matches that resolved repository, rejecting/ignoring matches in unrelated stacks.

### Proof of Concept
Minitest plan (no live GitHub):
1. Create two stacks, `victim_stack` (repo `org/victim`) and `attacker_stack` (repo `org/attacker-fork`), sharing the Shipit github_app org config.
2. In `victim_stack`, build commits `c1` (ancestor, lacking `ci/required` status → `blocking?` true) and `c2` (newer, undeployed). Set `victim_stack.cached_deploy_spec` `blocking_statuses` to include `context: 'ci/required'`.
3. In `attacker_stack`, create a `Commit` with the *same sha* as `c1` (simulating a fork sharing history), belonging to `attacker_stack`'s `stack_id`.
4. Assert precondition: `refute c2.deployable?` (blocked because `c1.blocking?` is true).
5. Invoke `Shipit::Webhooks::Handlers::StatusHandler.new(...).call(params)` (or POST to `/webhooks` with `X-Github-Event: status`) with `sha: c1.sha, state: 'success', context: 'ci/required'` and `repository.full_name: 'org/attacker-fork'`.
6. Assert both commits with that sha received the status (`c1.reload.statuses.last.context == 'ci/required'`), and now `assert c2.reload.deployable?` — proving `victim_stack`'s gate was cleared by a webhook scoped to `attacker_stack`'s repository.

### Citations

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

**File:** app/models/shipit/commit.rb (L231-237)
```ruby
    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/status/common.rb (L46-48)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
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
