### Title
Cross-repository Commit status forgery via `StatusHandler#process` bypassing repository scoping - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits solely by `Commit.where(sha: params.sha)` and never calls the inherited `Handler#stacks`/`repository_name` scoping that every other handler (e.g. `PushHandler`) relies on. Because `verify_signature` in `WebhooksController` only authenticates that a request originated from a GitHub App configured for the payload's `repository.owner.login`/`organization.login`, and does not confirm that the specific `repository.full_name` in the payload is the repository the webhook was actually issued for, any correctly-signed "status" event naming an arbitrary or absent repository can update `CommitStatus` rows for commits belonging to a completely unrelated stack, as long as the attacker knows (or guesses) a real SHA tracked by Shipit.

### Finding Description
The broken binding is:

`Handler#repository_name` (i.e. `payload.dig('repository','full_name')`, used by `Handler#stacks` at app/models/shipit/webhooks/handlers/handler.rb:32-38) **==** the repository scope actually enforced before `Commit` rows are mutated.

`PushHandler#process` (app/models/shipit/webhooks/handlers/push_handler.rb:12-17) honors this binding: it calls `stacks.not_archived.where(branch:)`, so a push webhook can only affect stacks belonging to `Repository.from_github_repo_name(repository_name)`.

`StatusHandler#process` (app/models/shipit/webhooks/handlers/status_handler.rb:20-24) does not:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
It never reads `payload.dig('repository','full_name')` and never calls `stacks`. `Commit.where(sha:)` is a global, unscoped lookup across all repositories/stacks tracked by the Shipit instance.

`WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) resolves the GitHub App via `repository_owner`, which itself is read straight from the same untrusted payload (`params.dig('repository','owner','login') || params.dig('organization','login')`, line 59-62). It validates the HMAC signature against that app's shared secret, proving only that *some* app with that secret sent the request — it does not verify that the app is actually installed on, or authorized for, the specific repository named in the payload, nor does it reject events where `repository.full_name` is absent, spoofed, or points to a repository not tracked by any `Stack`.

Attack flow:
1. Attacker controls (or is a collaborator on) any repository whose organization has a configured Shipit GitHub App and can trigger (or directly emit) a `status` webhook signed with that app's `webhook_secret` — this is explicitly listed as the only precondition ("valid webhook_secret for any configured app").
2. The attacker sets `sha` in the payload to a real commit SHA belonging to a target stack in a different, unrelated repository, and sets `state`/`context`/`description` to whatever forged value they want (e.g. `success`).
3. `drop_unhandled_event` passes (status is handled), `verify_signature` passes because the signature is valid for the attacker's own app/secret pairing on the owner they control.
4. `StatusHandler#process` runs `Commit.where(sha: <target sha>)`, finds the commit row belonging to the victim stack (global table, no repo filter), and calls `commit.create_status_from_github!(params)`, writing a forged `CommitStatus` for that commit.

Because commit statuses are one of the gating mechanisms used by Shipit to decide whether a commit/stack is deployable (CI status checks), this allows an attacker with no relationship to the victim repository to inject fabricated `success`/`failure` statuses into another repository's commit history as tracked by Shipit, potentially unblocking or blocking that stack's deploy pipeline.

None of the existing guards catch this: `verify_signature` binds only to app/owner, not to the specific repository record or a `Stack`; `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema for `StatusHandler` (`sha`, `state`, `description`, `target_url`, `context`, `created_at`, `branches`) never declares or validates `repository`/`repository.full_name` at all, so there's no schema-level enforcement either.

### Impact Explanation
A successful forged "status" webhook writes a `CommitStatus` row (via `Commit#create_status_from_github!`) against a real commit belonging to a repository/stack the attacker does not own or control, without that repository's own webhook ever having sent the event. This is a cross-repository/stack write that bypasses the very repository-scoping mechanism (`Handler#stacks`/`repository_name`) every sibling handler enforces, matching the "payload for one repository mutating another's stack/commit" Critical category. It is repeatable against any repository/stack whose commit SHAs are discoverable (SHAs are frequently public via GitHub itself), and can be executed by anyone controlling a single app's webhook secret for their own repository/organization, without needing any credential belonging to the victim.

### Likelihood Explanation
Preconditions are minimal: the attacker only needs a "valid webhook_secret for any configured app" (per the given preconditions) — i.e., control over a repository/org that has its own Shipit GitHub App installed, which is a normal, unprivileged position for many real-world Shipit deployments with multiple onboarded orgs/repos. The attacker needs to know a real commit SHA in the target stack, which is trivial for public repositories or repositories with any commit-hash leakage (PRs, CI logs, etc.). No interaction with Shipit's session, API tokens, or GitHub App private keys is required. The attack is fully repeatable and requires only crafting one HTTP POST per forged status.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the repository indicated in the verified payload, mirroring `PushHandler`/`PullRequest` handlers, e.g.:
```ruby
def process
  Commit.where(sha: params.sha, stack_id: stacks.select(:id)).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
Additionally, require `repository.full_name` in the `StatusHandler` `params` schema (and reject the event if it doesn't resolve to a known `Repository`), and consider strengthening `WebhooksController#verify_signature` to also assert that the resolved GitHub App/installation actually has access to `repository.full_name`, not merely to the owner login.

### Proof of Concept
Add a minitest to `test/models/webhooks/handlers/status_handler_test.rb` style file (outside `test/**` scope note aside — this is where the fix's regression test belongs):
1. Create two stacks/repositories, `repo_a` and `repo_b`, each with a `Commit` row for a distinct known `sha_a` and `sha_b`.
2. Build a `status` payload with `sha: sha_b` (belonging to `repo_b`) but `repository.full_name` set to `repo_a/repo_a` (or omitted).
3. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
4. Assert that `Commit.find_by(sha: sha_b).statuses` now contains the forged status — i.e., `repo_a`'s webhook mutated `repo_b`'s commit, even though `Handler#repository_name` for the payload resolves to `repo_a`, not `repo_b`.
5. Contrast with `Shipit::Webhooks::Handlers::PushHandler.call` using the same cross-repository payload shape and assert it does **not** touch `repo_b`'s stack, because `PushHandler#process` uses `stacks.where(branch:)` which is properly scoped by `repository_name`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```
