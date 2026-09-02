### Title
`StatusHandler#process` resolves commits by SHA only, letting a signed webhook from an attacker's own fork trigger `:deployable_status` hook delivery on a victim stack with attacker-controlled `description`/`target_url` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`, `app/models/shipit/commit.rb`)

### Summary
`StatusHandler#process` looks up commits solely by `sha`, with no check that the webhook's `repository.full_name` matches the stack owning that commit. Because Git SHAs are content-addressed and identical across a fork and its upstream, an attacker who registers their own fork as a Shipit stack (and can legitimately sign webhooks for their own repository) can send a `status` event for a shared commit and have it applied to the victim's `Commit` record, firing `Hook.emit(:deployable_status, victim_stack, payload)` with attacker-chosen `description`/`target_url`.

### Finding Description
The intended binding is: `payload.dig('repository', 'full_name') == commit.stack.repository.full_name` — a status event should only ever affect commits belonging to the repository/stack that the webhook was verified for. This binding is broken in `StatusHandler#process`: [1](#0-0) 

`Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` iterates over **every** `Commit` record across **all** stacks/repositories that shares that SHA, with no repository filter — unlike the generic `Handler` base class, which does expose a repository-scoped `stacks` helper that is simply not used here: [2](#0-1) 

`create_status_from_github!` then calls `add_status`, which emits the `:deployable_status`/`:commit_status` hooks against the commit's own `stack` (the victim's stack), carrying `description`/`target_url` straight from the untouched webhook payload: [3](#0-2) [4](#0-3) 

`verify_signature` in `WebhooksController` only checks that the HMAC signature is valid for the `repository_owner`/`organization` **present in the attacker's own payload** — it says nothing about which `Commit` rows in the database get matched: [5](#0-4) 

Exploit flow: the attacker forks the victim's GitHub repository (preserving upstream commit SHAs, since Git SHAs are content hashes), gets their fork registered as a Shipit stack (requires the Shipit GitHub App/organization to be known to `Shipit.github(organization: ...)` for the attacker's own org — the attacker's org, not the victim's), then sends a legitimately-self-signed `status` webhook for that shared SHA with an arbitrary `description`/`target_url`. `StatusHandler` matches the SHA against the victim's `Commit` too, and `Hook.emit(:deployable_status, victim_stack, payload)` fires to every Hook URL the victim configured for their stack, carrying the attacker's strings. None of `verify_signature`, `drop_unhandled_event`, or the `ExplicitParameters` schema restrict which `Commit`/`Stack` is affected — they only validate the *signature* and *shape* of the payload, not repository ownership of the target records.

### Impact Explanation
The victim's Shipit-configured outbound Hook URLs (which may be internal endpoints, Slack integrations, deploy-orchestration systems, etc.) receive a webhook call carrying the victim's stack/commit identifiers alongside completely attacker-controlled `description` and `target_url` strings. This is "a payload for one repository mutating another's stack[/]commit" — explicitly listed as Critical impact. It is repeatable against any victim repository that shares commit history with a repository the attacker controls (i.e., any public repo an attacker can fork), and scales across every stack/commit sharing that SHA.

### Likelihood Explanation
Preconditions: the attacker needs (1) a fork of the victim repo (trivial, public GitHub feature), (2) that fork registered as a Shipit stack under an organization Shipit already trusts (i.e., the Shipit GitHub App installed/known for that org) so `verify_signature` passes with the attacker's own legitimately-computed signature. No victim secrets, tokens, or sessions are needed. Feasibility is high wherever Shipit is configured to allow self-service stack creation across multiple GitHub orgs/installations; the attack is fully repeatable and requires only standard, unprivileged GitHub actions plus one HTTP POST to `/webhooks`.

### Recommendation
In `StatusHandler#process` (and the analogous check-run handler), scope the commit lookup to the repository identified in the verified webhook payload, e.g. filter through `Repository.from_github_repo_name(payload.dig('repository','full_name'))&.stacks&.commits` rather than a bare `Commit.where(sha: ...)`, mirroring the `stacks`/`repository_name` helper already defined in `Handler`.

### Proof of Concept
1. Create two `Stack`s (`victim_stack` for repo `victim/repo`, `attacker_stack` for repo `attacker/fork`) each with a `Commit` sharing the same `sha`.
2. Stub `Shipit::Hook.emit` to capture calls.
3. Build a `status` webhook payload with `repository.full_name = 'attacker/fork'`, `sha` = the shared SHA, `description = 'ATTACKER_STRING'`, `target_url = 'https://attacker.example/x'`.
4. Invoke `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly (bypassing controller-level signature concerns, since signature only validates payload authenticity for `attacker/fork`, not which `Commit` rows get updated).
5. Assert `Hook.emit` was called with `:deployable_status`, `victim_stack`, and a payload whose `deployable_status`/underlying `Status` has `description == 'ATTACKER_STRING'` and `target_url == 'https://attacker.example/x'` — i.e., assert the equality `commit.stack == victim_stack` while `payload.dig('repository','full_name') == 'attacker/fork' != victim_stack.repository.full_name`, proving the repository-scope binding is violated.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
