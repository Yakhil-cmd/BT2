### Title
`StatusHandler#process` mutates commit statuses across all stacks sharing a SHA, with no repository binding check - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler`'s `params` schema only requires `:sha` and `:state` and never consults `payload.dig('repository', ...)`, and `process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no scoping to the repository/stack that authenticated the webhook. Since `sha` is indexed per `(stack_id, sha)` rather than being globally unique [1](#0-0) , an attacker who owns a fork of a target repository (sharing identical git commit SHAs with the upstream) can send a signed status webhook from their own repo/app pairing that updates the commit status of the same SHA recorded under a completely different, victim stack.

### Finding Description
The broken binding: the code should enforce `commit.stack.repository == webhook_authenticated_repository`, but no such equality is ever checked. `WebhooksController#verify_signature` only proves the payload was signed by the GitHub App belonging to `repository_owner` (derived from `params.dig('repository', 'owner', 'login')`) [2](#0-1) ; it does not bind the handler's subsequent DB writes to that repository. `Handler#initialize` just parses the payload through the class's `ExplicitParameters` schema [3](#0-2) , and `StatusHandler`'s schema requires only `:sha`/`:state` and never requires or reads `:repository` [4](#0-3) . `process` then does a global lookup: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [5](#0-4) . `create_status_from_github!` writes the status using the commit's own `stack_id` [6](#0-5)  and pushes an update via `Hook.emit` and `stack.schedule_merges` [7](#0-6)  - i.e. it can flip the deployability/blocking status of a commit in a stack that the attacker never authenticated against and does not own.

Exploit flow: attacker forks the victim's public repository into their own GitHub account (forks share identical commit objects/SHAs with upstream), installs/enables their attacker-owned Shipit-connected GitHub App on the fork, and sends `POST /webhooks` with `X-Github-Event: status` and a `status` payload whose `sha` matches a real commit SHA that also exists in the victim's tracked Shipit stack. `verify_signature` succeeds because it is validated against the attacker's own app/secret bound to their own fork's owner [8](#0-7) . `StatusHandler.call(params)` then matches and mutates the victim's `Commit` row purely by `sha`, regardless of which repository field, if any, is present in the payload.

Existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema) do not close this gap: `verify_signature` only checks who signed the request, not which stack's data gets touched, and the schema simply never asks for `:repository` at all.

### Impact Explanation
A request forges a Shipit commit-status mutation for a stack the attacker did not authenticate against: it can flip a commit from failing to `success`, altering `deployable?` (`Commit#deployable?`) and triggering `stack.schedule_merges` / continuous delivery scheduling for the victim's stack [9](#0-8) . This is a cross-tenant write: one repository's webhook payload mutates another repository's stack/commit state, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." The attack is repeatable against any victim repository that has a public fork-able history overlapping SHAs with a stack tracked in the same Shipit instance.

### Likelihood Explanation
Preconditions: the attacker needs to own/control a repository (e.g., a fork of the target) registered with a Shipit-connected GitHub App so they can obtain a valid `X-Hub-Signature` for their own app/secret, and the victim's stack must contain a commit with a SHA reachable by the attacker (trivially true for any commit that predates the fork, which is the common case). No privileged role, no Shipit session, and no victim secrets are required - this matches the described unprivileged attacker capability set. The attack is cheap (one HTTP POST) and repeatable.

### Recommendation
Require and validate `:repository` in `StatusHandler`'s param schema, and scope the `Commit` lookup to the stack(s) belonging to the authenticated repository, e.g. `stacks.commits.where(sha: params.sha)` (using `Handler#stacks`, which is already scoped via `Repository.from_github_repo_name(repository_name)`), instead of the unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create two stacks/repositories, `stack_a` (repo `org/victim`) and `stack_b` (repo `attacker/fork`).
2. Create `commit_a` under `stack_a` with `sha: "deadbeef..."`; assert `commit_a.status.state != "success"`.
3. Build a `status` webhook payload with `sha: "deadbeef..."`, `state: "success"`, and `repository.full_name` set to `attacker/fork` (i.e., referencing `stack_b`, not `stack_a`).
4. Call `Shipit::Webhooks::Handlers::StatusHandler.call(params)` with that payload.
5. Assert `commit_a.reload.status.state == "success"` even though the payload's `repository` pointed to `stack_b`/`attacker/fork`, proving the write escaped repository scoping - i.e. assert the binding `commit.stack.repository == payload.repository` is violated (`stack_a.repository != attacker_repo` yet `commit_a` was mutated).

### Citations

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-10)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L19-24)
```ruby
        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
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
