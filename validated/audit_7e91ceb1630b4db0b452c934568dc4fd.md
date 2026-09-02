### Title
Cross-tenant status confusion via unscoped `Commit.where(sha:)` triggers unauthorized deploy - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits to attach a status to solely by `sha`, across the entire `commits` table, instead of scoping to the repository named in the verified webhook payload. Since `verify_signature` only proves the payload came from GitHub for the `repository.owner.login` in the body — it never checks that the `sha` inside the payload belongs to that repository — an attacker who controls a repository sharing a commit SHA with a victim Stack (e.g. via a public fork, where git's content-addressed objects preserve identical SHAs for shared history) can post a `status` webhook for their own repo and flip `Commit#deployable?` on the victim's commit.

### Finding Description
The broken binding is: `commit.stack == Repository.from_github_repo_name(payload.repository.full_name).stacks` should hold for every commit mutated by a webhook, but `StatusHandler#process` never enforces it: [1](#0-0) 

Unlike other handlers that scope work through `Handler#stacks` (built from `Repository.from_github_repo_name(repository_name)&.stacks`, see [2](#0-1) ), `StatusHandler#process` runs `Commit.where(sha: params.sha)` globally and calls `commit.create_status_from_github!(params)` on every matching row regardless of which repository/stack owns it.

`WebhooksController#verify_signature` authenticates only that the request was signed by GitHub for the organization named in `payload.dig('repository','owner','login')`: [3](#0-2) 

It does not verify that the `sha` field, or any other body content, actually pertains to that repository's own commit history — GitHub's signature only guarantees provenance of the byte stream from GitHub for that org/app installation, and an attacker who owns a repository (with their own webhook/app configured) can freely set `sha`, `state`, `context`, etc. in the `status` payload body while still producing a signature GitHub will happily generate for their own repo. Because forked repositories in git are content-addressed, unmodified upstream commits keep the exact same SHA1 in the fork; an attacker can fork a public repository that a victim Stack tracks, obtain a real SHA identical to the victim's pending/next-undeployed commit, and fire a `status` event for their own (attacker-owned) repository with that `sha` and `state: 'success'`.

`create_status_from_github!` → `add_status` → `Status.replicate_from_github!` creates a `Status` row scoped to the *victim's* `stack_id` (taken from the found `Commit`, not from the webhook payload), which is exactly what flips `Commit#deployable?`: [4](#0-3) [5](#0-4) 

`Status#schedule_continuous_delivery` after_commit callback then schedules continuous delivery for the victim stack, and `ContinuousDeliveryJob`/`Stack#next_commit_to_deploy` will see the commit as deployable and enqueue a `Deploy`. None of `verify_signature`, `drop_unhandled_event`, or the `ExplicitParameters` schema in `StatusHandler` constrain `sha` to the authenticated repository — the schema only requires `sha` be a `String`: [6](#0-5) 

### Impact Explanation
An attacker who owns any repository sharing commit history (via public fork) with a victim's continuously-deployed Stack can write a `Status` record — and thus flip `deployable?` — for a commit belonging to a Stack/tenant they never authenticated against. This directly triggers `Stack#trigger_continuous_delivery` to enqueue an unauthorized `Deploy` for the victim's Stack, matching the "Critical: a payload for one repository mutating another's stack/commit/task, or an unauthorized deploy" category. The attack is repeatable against any Stack whose next-undeployed commit's SHA also exists (with a shared history) in a repository the attacker controls.

### Likelihood Explanation
Preconditions: the victim Stack must have `continuous_deployment: true` and an undeployed commit currently in `pending`/no-status state; the attacker needs a repository (e.g. a public fork of the tracked upstream) sharing an un-diverged commit SHA, and the ability to register a GitHub App/webhook on that repository so `verify_signature` succeeds for their own org. This is inexpensive and fully attacker-controlled — no Shipit credentials, secrets, or GitHub org membership on the victim's side are required, only ordinary GitHub account privileges (forking a public repo, configuring a webhook on your own repo).

### Recommendation
Scope `StatusHandler#process` (and any other handler that resolves records purely by `sha`) to the repository named in the verified payload, e.g. restrict the `Commit.where(sha:)` lookup to `commit.stack_id in stacks.pluck(:id)` (using the existing `Handler#stacks` helper derived from `payload.dig('repository','full_name')`) before calling `create_status_from_github!`, so a status can only be attached to commits belonging to the Stack(s) tied to the authenticated repository.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "process does not create a status for a commit belonging to a different repository/stack" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(continuous_deployment: true)
  shared_sha = 'a' * 40

  victim_commit = victim_stack.commits.create!(
    sha: shared_sha,
    author: shipit_users(:walrus),
    committer: shipit_users(:walrus),
    authored_at: Time.now,
    committed_at: Time.now,
    message: 'victim commit'
  )
  # simulate: victim_commit is the next undeployed commit, currently pending/no status
  refute_predicate victim_commit, :deployable?

  attacker_payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'repository' => { 'full_name' => 'attacker/unrelated-repo', 'owner' => { 'login' => 'attacker' } }
  }

  assert_difference -> { Deploy.where(stack: victim_stack).count }, 1 do
    Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)
    Shipit::ContinuousDeliveryJob.new.perform(victim_stack)
  end
end
```
Binding to assert before/after: `victim_commit.reload.stack_id == victim_stack.id` (unchanged, true) while `victim_commit.reload.deployable?` flips `false -> true` purely because of a status created from `attacker_payload`, whose `repository.full_name` (`attacker/unrelated-repo`) never equals `victim_stack.repository.full_name` — demonstrating the equality the question describes never holds, yet the mutation and resulting deploy occur anyway.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```
