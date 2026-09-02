### Title
Cross-repository Status injection via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely by `sha`, with no check that the webhook's `payload['repository']['full_name']` matches the repository owning the target commit's stack. Because git commit SHAs are content hashes shared across forks/mirrors of the same repository, an attacker who owns a fork (or any repo with an identical commit) can trigger a validly-signed "status" webhook from *their own* repository and have Shipit write an attacker-controlled `Status` row (`context`, `description`, `target_url`) onto a victim stack's commit that never authenticated against that webhook.

### Finding Description
The binding the question claims should hold is:
`payload['repository']['full_name'] == commit.stack.repository.full_name` for every `Commit` mutated by `create_status_from_github!`.

Tracing the call path:
- `WebhooksController#create` dispatches to `Shipit::Webhooks.for_event(event)` handlers after `verify_signature`, which only checks that the raw payload is HMAC-signed by the GitHub App keyed on `repository_owner` (`params.dig('repository','owner','login')`) — [1](#0-0) . This proves the payload came from *some* GitHub organization/app installation, but says nothing about which repository's stacks may be mutated.
- `Handler` base class exposes a `stacks`/`repository_name` helper specifically meant to scope handler effects to the webhook's own repository — [2](#0-1) .
- `StatusHandler#process`, unlike handlers that use `stacks`, ignores repository scoping entirely and queries commits globally by SHA: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — [3](#0-2) .
- `Commit#create_status_from_github!` calls `statuses.replicate_from_github!(stack_id, github_status)`, which persists attacker-supplied `state`, `description`, `target_url`, `context`, `created_at` via `find_or_create_by!` keyed on the *victim's own* `stack_id` — [4](#0-3) [5](#0-4) .

Exploit flow: attacker forks or otherwise owns a repository containing a commit whose SHA also exists in a victim's tracked repository (trivial for public open-source forks, since git SHAs are content-addressed and identical across clones/forks until rewritten). Attacker installs/configures a GitHub webhook on their own repository pointed at the Shipit host's `/webhooks` endpoint for the `status` event — this is a legitimate action available to any repository owner, and if Shipit's GitHub App/webhook secret is shared per-installation (common for GitHub Apps), GitHub itself computes a valid signature without the attacker ever needing the secret. The attacker (or GitHub, replaying their own commit status) sends a `status` webhook with the colliding `sha`, `context`, and `description`. `StatusHandler#process` finds the victim's `Commit` row purely by SHA match, and writes the attacker-chosen `context`/`description`/`target_url` into a `Status` belonging to the victim's stack.

Existing guards fail to stop this because `verify_signature` validates *that the payload is a real webhook from some org*, not *that the org matches the target stack's repository*; and `drop_unhandled_event`/`ExplicitParameters` only validate the shape of `status` payloads, not their repository binding.

### Impact Explanation
An attacker who never authenticated against a victim's repository/stack causes arbitrary strings to be written into a `Status` row on the victim stack's commit, visible in that stack's deploy/commit UI to the victim's team. This is a repository-A-payload-mutating-repository-B's-commit/stack scenario, matching the "Critical" category ("a payload for one repository mutating another's stack, commit, task or team"). It is repeatable against any victim repository that shares commit SHAs with a repository the attacker controls (forks of public projects being the common case), and the attacker fully controls `context`, `description`, `target_url`, and `state` content injected into the victim's UI/task stream.

### Likelihood Explanation
Preconditions: (1) the victim stack must track a commit whose SHA also exists in a repository the attacker owns/controls (satisfied whenever the victim stack tracks a public repo the attacker can fork with unmodified history, or any repo sharing history), and (2) the attacker must be able to get Shipit to accept a signed `status` webhook keyed to their own repository/org, which is exactly the access explicitly granted to attackers in this threat model ("push to a fork ... and emit webhooks from a repository they own"). No Shipit session, API token, or knowledge of `webhook_secret`/`api_clients_secret` is required — the attacker relies on GitHub's own webhook signing for a repo/org they legitimately control. This is a self-service, repeatable attack requiring no privileged Shipit role.

### Recommendation
Scope `StatusHandler#process` (and any other SHA-only handler) to the webhook's own repository before mutating commits, e.g. restrict the `Commit` lookup to `stacks` derived from `repository_name` (as the `Handler` base class already provides), such as:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This enforces `payload['repository']['full_name'] == commit.stack.repository.full_name` before any write.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, illustrative — final location out of scope per rules but describing the assertions):
1. Create `victim_stack` for repo `victim/repo` and `attacker_stack` (or no stack at all) for repo `attacker/fork`, both containing a `Commit` with the identical `sha: "deadbeef"` (simulating a shared fork commit).
2. Build a `status` webhook payload with `repository.full_name = "attacker/fork"`, `sha: "deadbeef"`, `context: "attacker-token-lookalike"`, `description: "AKIAEXAMPLE_SECRET"`.
3. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly (bypassing signature verification, which is out of scope for this model-level proof).
4. Assert:
   - `victim_commit.statuses.last.context == "attacker-token-lookalike"`
   - `victim_commit.statuses.last.description == "AKIAEXAMPLE_SECRET"`
   - i.e., `payload['repository']['full_name'] != victim_stack.repository.full_name` yet the write occurred, demonstrating the broken binding.

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

**File:** app/models/shipit/status.rb (L23-33)
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
```
