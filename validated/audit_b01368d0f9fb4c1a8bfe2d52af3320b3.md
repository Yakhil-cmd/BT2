### Title
`StatusHandler#process` writes GitHub statuses to commits across all repositories without scoping to the webhook's originating repository - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits with a global `Commit.where(sha: params.sha)` query and never calls `stacks` or `repository_name`, unlike every other `Handler` subclass which scopes writes via `Repository.from_github_repo_name(repository_name)&.stacks`. Because `sha` is not repository-scoped in this query, an attacker who owns any Shipit-registered repository (and therefore controls a valid `webhook_secret`) can send a `status` webhook naming their own repository but containing the `sha` of a commit that also exists in an unrelated stack, causing a `Status` record to be created on that unrelated commit.

### Finding Description
The binding that holds for every other handler is:
`mutated_stack.repository.full_name == payload.dig('repository', 'full_name')`

This is enforced through `Handler#stacks` [1](#0-0) , which resolves the target stacks strictly from `Repository.from_github_repo_name(repository_name)`, where `repository_name` is `payload.dig('repository', 'full_name')`.

`StatusHandler#process`, however, never calls `stacks` or `repository_name` [2](#0-1) . Instead it does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
This queries `Commit` globally by `sha` across every stack/repository in the Shipit instance, with no filter tying the match back to `payload['repository']['full_name']`. `commit.create_status_from_github!` then calls `add_status`/`statuses.replicate_from_github!` on that commit, unconditionally writing a `Status` row on it [3](#0-2) .

`WebhooksController#verify_signature` only proves that the request was signed by the GitHub App belonging to `repository_owner = payload.dig('repository','owner','login')` [4](#0-3) . It proves the attacker legitimately controls the named repository - it does not, and cannot, prove anything about which `sha` values are permitted in the payload. Git commit SHAs are content-addressed and are not secrets: identical commit content (e.g. from forks sharing history, or commits whose SHA is simply known/observed publicly on GitHub) produces identical SHAs in any repository. Because `StatusHandler` never checks that the resolved `Commit#stack.repository.full_name` matches the signed-for repository, an attacker-controlled, validly-signed webhook for their own repo can target and mutate a commit belonging to a completely different, victim-owned stack.

No other guard closes this gap: `drop_unhandled_event` only checks that a handler is registered for the event type, `ExplicitParameters` only validates the shape of `sha`/`state`/etc., and there is no `Repository`/`Stack` scoping performed anywhere in `StatusHandler`.

### Impact Explanation
A successfully forged `status` webhook writes a `Status` record onto a commit belonging to a stack the attacker does not own and never authenticated against. This is a cross-tenant write: `add_status` can flip `previous_status`/`new_status`, emit `Hook.emit(:commit_status, ...)` and `Hook.emit(:deployable_status, ...)` on the victim's stack, and call `stack.schedule_merges` if the injected status is `pending` or `success` [5](#0-4) . Since `deployable?` depends on required/blocking statuses, an attacker can potentially force a victim commit into (or out of) a deployable state, or trigger continuous-delivery scheduling on a stack they have no relationship to. This matches "a payload for one repository mutating another's stack, commit ... " — Critical severity per the rubric.

### Likelihood Explanation
Preconditions are minimal: the attacker only needs any repository registered in Shipit with a valid `webhook_secret`/GitHub App installation for their own org (something any external GitHub org owner can set up if Shipit is configured to auto-onboard, or trivially satisfy if they already have a legitimate, unrelated repo on the platform). No Shipit session, API token, or team membership is required. The only additional requirement is knowledge of a target `sha` that exists in the victim's stack, which is commonly public (GitHub commit pages, forks, CI logs) and not a secret. This makes the attack straightforward and repeatable against any commit SHA reachable by the attacker across arbitrary stacks.

### Recommendation
Scope `StatusHandler#process` the same way as other handlers: resolve the target stacks via `stacks` (i.e., `Repository.from_github_repo_name(repository_name)&.stacks`) and restrict the `Commit` lookup to commits belonging to those stacks, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or joining `Commit` to `Stack`/`Repository` and filtering on `repository.full_name == repository_name`, before calling `create_status_from_github!`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, would need to be added under `test/`, out of scope to write here but the design is):
```ruby
test "process does not scope by stacks/repository_name and writes cross-tenant status" do
  victim_stack = shipit_stacks(:shipit)
  victim_commit = victim_stack.commits.create!(sha: "deadbeef" * 5, message: "victim commit")

  attacker_payload = {
    "repository" => { "full_name" => "attacker/unrelated-repo" },
    "sha" => victim_commit.sha,
    "state" => "success",
    "context" => "ci/attacker"
  }

  handler = Shipit::Webhooks::Handlers::StatusHandler.new(attacker_payload)
  handler.expects(:stacks).never
  handler.expects(:repository_name).never

  handler.process

  assert victim_commit.statuses.reload.exists?(state: "success", description: nil, target_url: nil),
         "expected attacker-controlled webhook to write a Status onto a commit in an unrelated stack"
end
```
This demonstrates both halves of the equality: `victim_stack.repository.full_name` ("shopify/shipit-engine" or fixture equivalent) never equals `attacker_payload['repository']['full_name']` ("attacker/unrelated-repo"), yet the write to `victim_commit.statuses` still succeeds, and `stacks`/`repository_name` are never invoked, confirming the missing scope check unique to `StatusHandler`.

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
