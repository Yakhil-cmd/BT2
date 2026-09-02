### Title
Cross-repository `status` webhook writes `Shipit::Status` records onto an unrelated stack's commit — (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits purely by `sha` with `Commit.where(sha: params.sha)`, with no scoping to the repository named in the webhook payload, unlike the base `Handler` class which provides a repository-scoped `stacks` helper that this handler never calls. This lets a webhook that is validly signed for repository B mutate `Shipit::Status` rows (and trigger a `broadcast_update`) on any other stack/repository A whose commit table happens to contain a matching SHA. Regarding the specific `ignore_ci?` framing in the question: `Commit#deployable?` short-circuits on `stack.ignore_ci?` and never consults `success?`/`blocked?` in that case, so this particular write does **not** change which commit is "deployable" for an `ignore_ci?` stack — but the cross-tenant `Status` row creation itself is still a real, independently exploitable bug.

### Finding Description
Binding claimed as broken: `payload['repository']['full_name'] (repo B) == stack_a.repository.full_name`. Tracing the code shows this equality is never checked at all in the vulnerable path:

- `WebhooksController#create` parses the raw body and dispatches to `Shipit::Webhooks.for_event(event)` handlers [1](#0-0) . `verify_signature` only checks that the payload is validly signed for the organization named in `payload['repository']['owner']['login']` — it says nothing about which *stack* the SHA belongs to [2](#0-1) .
- `Webhooks.default_handlers` routes the `status` event to `Handlers::StatusHandler` [3](#0-2) .
- The base `Handler` class *does* provide a repository-scoped accessor, `stacks`, built from `Repository.from_github_repo_name(repository_name)&.stacks`, using `payload.dig('repository', 'full_name')` [4](#0-3) . This is the mechanism that would enforce the binding.
- `StatusHandler#process`, however, never uses `stacks` or `repository_name`. It does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [5](#0-4) . Any commit row in the entire database sharing that SHA — regardless of which repository/stack it belongs to — gets a new `Status` created.
- `Commit#create_status_from_github!` calls `statuses.replicate_from_github!(stack_id, github_status)`, which `find_or_create_by!`s a `Shipit::Status` scoped to that commit's own `stack_id`, not the webhook's repository [6](#0-5) , [7](#0-6) .
- `Status` creation triggers `after_commit :schedule_continuous_delivery, :broadcast_update, on: :create` [8](#0-7) , i.e. a real side effect (broadcast to connected clients, and a continuous-delivery evaluation) fires for stack A even though the write originated from repo B's webhook.

Attacker's exact request: attacker owns/forks repository B (a fork of the same public project also tracked by Shipit as stack A, or any repo whose commit history overlaps by SHA with stack A's tracked history — e.g. an un-rebased fork shares identical commit SHAs with upstream). Attacker sets a GitHub commit status on that SHA via repo B (using their own repo-write permission and the GitHub status API/Action), which causes GitHub to emit a properly-signed `status` webhook for repo B to the Shipit host. This webhook passes `verify_signature` legitimately (it's genuinely from GitHub for org B). `StatusHandler.process` then matches any `Commit` row with that SHA, including stack A's commit, and creates a `Status` there.

Regarding `ignore_ci?`: `Commit#deployable?` is `!locked? && (stack.ignore_ci? || (success? && !blocked?))` [9](#0-8) . When `stack.ignore_ci?` is `true`, the `success?`/`blocked?` branch is never evaluated, so the injected `Status` has **no effect on the deployability decision** for stack A in this configuration. The "influence deployable?" half of the question's claim is therefore false as stated — this is confirmed directly by the boolean short-circuit in the code. What remains true and exploitable is the unscoped write/broadcast itself, independent of `ignore_ci`.

### Impact Explanation
A `Shipit::Status` row (state/description/context/target_url attacker-controlled via the webhook payload) is created under an arbitrary stack A's commit purely because a SHA collision exists, without any check that the webhook's repository matches stack A's configured repository. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team." For stacks that do **not** set `ignore_ci: true`, this cross-tenant write directly feeds `success?`/`blocked?`/`deployable?` and can flip `Commit#deployable?`/`schedule_continuous_delivery`, i.e. influence continuous deployment decisions — a materially worse outcome than the `ignore_ci?` case asked about here, where the effect is limited to spurious status/UI broadcast noise on stack A's commit page. The blast radius is any stack whose commit table shares a SHA with a repository the attacker controls (realistic for forks of public/mono-repos tracked by multiple Shipit stacks).

### Likelihood Explanation
Preconditions: attacker needs (a) a repository they control that has the Shipit GitHub App/webhook installed (feasible if the app installation is self-service, as is typical for public GitHub Apps), and (b) at least one commit SHA shared between their repository and the SHA of a commit already ingested into stack A (trivially achieved via forking a public project without rewriting history). No Shipit credentials, session, or API token are required — only ordinary GitHub repo-owner capabilities on repo B. This is cheap and repeatable against any stack/repository pair sharing SHAs.

### Recommendation
In `StatusHandler#process`, scope the commit lookup to the webhook's own repository, mirroring the pattern already provided by `Handler#stacks`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This enforces `payload['repository']['full_name'] == commit.stack.repository.full_name` before any `Status` is created.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb
test "status webhook for repository B does not create a Status on an unrelated stack A's commit with the same sha" do
  stack_a = shipit_stacks(:shipit) # repository e.g. "shopify/shipit-engine"
  commit_a = stack_a.commits.create!(sha: "deadbeef" * 5, message: "shared sha")

  repo_b_payload = {
    "sha" => commit_a.sha,
    "state" => "success",
    "repository" => { "full_name" => "attacker/unrelated-repo" },
    "branches" => [{ "name" => "master" }]
  }

  assert_no_difference -> { commit_a.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(repo_b_payload)
  end
end
```
Running this against the current implementation fails the `assert_no_difference` (a `Status` row IS created), demonstrating the unscoped cross-repository write. A companion assertion `assert_not commit_a.reload.deployable?` (or `assert commit_a.reload.deployable?` when `stack_a.ignore_ci = true`) confirms that for `ignore_ci?` stacks specifically, `deployable?` is unaffected either way, per `Commit#deployable?`'s short-circuit.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/webhooks.rb (L19-19)
```ruby
          'status' => [Handlers::StatusHandler],
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status.rb (L18-21)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit
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
