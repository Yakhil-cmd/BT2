### Title
Cross-Repository CI Status Forgery via Unscoped `Commit` Lookup in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits to attach a GitHub CI status to using a bare, repository-agnostic query — `Commit.where(sha: params.sha)` [1](#0-0)  — instead of scoping the lookup to the repository/organization that was actually authenticated by the webhook signature. This breaks the trust binding the report's bug-class maps to: *the organization/repository whose webhook signature was verified* ≠ *the repository/stack whose commit actually gets written*.

### Finding Description
`WebhooksController#verify_signature` authenticates a webhook payload only against the GitHub App/organization implied by the payload's own `repository.owner.login` (or `organization.login`) field, and validates the HMAC signature using that organization's `webhook_secret` [2](#0-1) . This proves the request genuinely came from GitHub for *some* repository within that organization/App installation — it does not, and cannot, further restrict which Shipit-tracked repository the event's contents are allowed to affect.

The base `Handler` class does provide a repo-scoping helper, `stacks`, built from `payload.dig('repository', 'full_name')` via `Repository.from_github_repo_name` [3](#0-2) , and other handlers such as `PushHandler` correctly use it to scope writes to the stacks of the payload's own repository [4](#0-3) .

`StatusHandler`, however, never uses `repository_name`/`stacks` at all. It queries `Commit` globally by `sha` across every repository/stack tracked by the entire Shipit instance [5](#0-4) , then calls `commit.create_status_from_github!(params)` for every match, which creates a `Status` row and fires side effects such as `schedule_continuous_delivery` and CI-state transition logic [6](#0-5) [7](#0-6) .

Because Git commit SHAs are content-addressed and not tied to any particular repository or organization, any actor who can trigger a validly-signed `status` webhook for *any* repository covered by a given GitHub App/webhook-secret installation (in the common single-secret Shipit deployment, this is every repository in the org) can forge a `sha` value equal to a commit SHA that is public knowledge for a completely different, unrelated stack tracked by the same Shipit instance, and inject an arbitrary CI status (`success`/`failure`/`pending`) onto that victim commit.

### Impact Explanation
This is a cross-repository write: a webhook whose signature only proves authenticity for organization/repo A is used to mutate CI/status state that belongs to an unrelated stack B tracked by the same Shipit instance. Attaching a fabricated `success` status can flip a victim commit's deployable state and trigger `schedule_continuous_delivery` [6](#0-5) , which in stacks with `continuous_deployment` enabled can result in an unauthorized deploy being kicked off for a commit that never actually passed the real CI checks. This matches the "Critical" bucket in scope: cross-repository writes / unauthorized deploy.

### Likelihood Explanation
No Shipit session, API token, webhook secret, or GitHub App credentials are required beyond the ability to make GitHub send a real `status` webhook for some repository under the shared App installation (e.g., pushing a commit and configuring a CI status on any repo the attacker legitimately owns within the org, or any repo the App is installed on). The SHA needed is public GitHub data, not a secret, and matching it to a victim commit requires no cryptographic collision — only knowledge of a target commit's SHA, which is trivially observable. This is a straightforward architecture gap (missing repo scoping in one handler) rather than a theoretical edge case, since sibling handlers (`Handler#stacks`, `PushHandler`) demonstrate the intended, correctly-scoped pattern that `StatusHandler` omits.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` to the stacks of the payload's own repository, mirroring `Handler#stacks`/`repository_name`, e.g. `stacks.joins(:commits).merge(Commit.where(sha: params.sha))`, so a webhook can only ever affect commits belonging to the repository it was actually issued and signed for.

### Proof of Concept
1. Shipit is configured with a single GitHub App/webhook secret shared by an organization (the common, documented configuration in `docs/setup.md`), tracking `victim-org/victim-repo` as a stack.
2. Attacker controls `victim-org/attacker-repo` (or any repo covered by the same App installation) and can trigger real GitHub `status` webhooks for it (e.g., via any CI integration they control on that repo).
3. Attacker observes a target commit SHA `S` in `victim-org/victim-repo` (public information, e.g. from the commit history) and sets the `context`/`state` (e.g. `state=success`) on their own `attacker-repo`'s commit with that identical value — achievable because SHAs are content-addressed, so pushing identical tree/commit metadata to `attacker-repo` yields the same SHA `S`.
4. GitHub sends a validly-signed `status` event for `attacker-repo` with `sha=S`, `state=success` to Shipit's `/github_hooks` endpoint. Signature verification passes because it only checks the org's webhook secret [2](#0-1) .
5. `StatusHandler#process` runs `Commit.where(sha: 'S')` [1](#0-0) , which also matches the commit in `victim-org/victim-repo`, and calls `create_status_from_github!` on it — writing a forged `success` status onto the victim's stack and potentially triggering continuous deployment.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-24)
```ruby
      class StatusHandler < Handler
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

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```
