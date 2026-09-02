### Title
Cross-organization commit-status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
The webhook signature verification in `WebhooksController#verify_signature` establishes trust for one specific GitHub organization (derived from the payload's `repository.owner.login`), but `Webhooks::Handlers::StatusHandler#process` writes a `Status` record by looking up commits **globally by SHA only**, with no scoping to the repository/organization that was actually authenticated. This breaks the equality: *"the organization that authenticated" == "the repository that is written."*

### Finding Description
`WebhooksController#verify_signature` picks the `GitHubApp` (and its `webhook_secret`) to validate the HMAC signature based on `repository_owner`, which is read straight out of the untrusted JSON payload (`params.dig('repository','owner','login')` or `params.dig('organization','login')`): [1](#0-0) [2](#0-1) 

This only proves the payload was sent by *some* organization that has a Shipit GitHub App installed and whose webhook secret matches — it says nothing about which repository's commits may legitimately be mutated. Compare this to the other default handlers, which correctly scope by repository before touching any records: [3](#0-2) [4](#0-3) [5](#0-4) 

`StatusHandler`, however, ignores `repository_name`/`stacks` scoping entirely and matches purely by SHA across the whole `Commit` table (i.e., across every stack and every organization configured in the Shipit instance): [6](#0-5) 

`Commit#create_status_from_github!` then persists this as a first-class `Status` row tied to the target commit/stack: [7](#0-6) [8](#0-7) 

Because git commit objects are content-addressed, an attacker who can read a target repository's public history (or otherwise knows the exact tree/parent/author/committer/message/timestamps of a target commit) can reproduce a commit with an **identical SHA** in a repository they control, in a *different* GitHub organization that also has the Shipit GitHub App installed (the multi-org setup this engine explicitly documents/supports, see `docs/setup.md` "Using Multiple Github Applications"). Setting a commit status on that colliding commit in their own, legitimately-configured organization produces a `status` webhook that passes `verify_signature` (it's genuinely signed by that attacker-controlled organization's webhook secret), yet `StatusHandler` will apply the forged status to the identical-SHA commit belonging to the *victim's* stack/organization.

### Impact Explanation
This is a cross-repository/cross-organization write of CI status data that this engine uses to gate deploys. `Commit#deployable?` and `#blocked?` rely directly on `Status`/`stack.required_statuses`/`stack.blocking_statuses`: [9](#0-8) 

An attacker who never had any access, permission, or webhook secret for the victim organization can inject a fabricated "success" status onto a victim's commit, satisfying `ci.require`/unblocking `ci.blocking` gates and enabling continuous delivery or a manual deploy to proceed on code that never actually passed CI — an unauthorized deploy path, matching the required "unauthorized deploy" impact category. It can equally be used to inject a "failure"/"error" status to deny-of-service a legitimate deploy pipeline for an unrelated organization's stack.

### Likelihood Explanation
Exploitation requires: (1) the target repository's commit content and metadata to be knowable (trivial for any public/open-source repository, and the tree/parent/author/committer/timestamps/message needed to reconstruct an identical git commit object are all visible via the GitHub API/git protocol without any special access), and (2) the attacker to control a repository in some other GitHub organization that has the Shipit GitHub App installed (satisfiable by simply registering/using their own org with Shipit, as multi-org support is a first-class, documented deployment configuration in this engine). No access to the victim org, no Shipit session, and no `webhook_secret`/`api_clients_secret` for the victim is needed — only a legitimately-signed webhook from the attacker's own org. This is a realistic, self-contained attack path within the engine's own trust model, not a theoretical one.

### Recommendation
Scope `StatusHandler#process` (and any other handler that currently trusts a bare SHA) to the repository identified in the payload, exactly as `PushHandler` and `CheckSuiteHandler` already do via `Handler#stacks`/`#repository_name`, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This ensures a status update can only be applied to commits belonging to the repository/organization that was actually authenticated for that webhook delivery, restoring the broken binding between "organization that authenticated" and "repository that is written."

### Proof of Concept
1. Attacker identifies a public target repository `victim-org/app` deployed via a Shipit instance, and a specific commit SHA `S` on its default branch that Shipit tracks as a `Commit`.
2. Attacker fetches the full commit metadata for `S` (tree hash, parent hash(es), author name/email/date, committer name/email/date, commit message) via the public GitHub API/git.
3. Attacker creates their own GitHub organization `attacker-org` (or uses an existing one) and installs a Shipit GitHub App for it, per the documented multi-org setup in `docs/setup.md`, giving them a valid `webhook_secret` for `attacker-org`.
4. Attacker locally constructs (via `git commit-tree`/`git hash-object`) a commit object using the exact same tree, parent(s), author, committer, and message/timestamps as commit `S`, reproducing the identical SHA `S` in a repository under `attacker-org`.
5. Attacker pushes this commit to their own repository and uses the GitHub Statuses API to set a `success` status with `sha: S` on their repo.
6. GitHub sends a `status` webhook to Shipit, signed with `attacker-org`'s webhook secret; `WebhooksController#verify_signature` resolves `repository_owner` to `attacker-org` and successfully verifies the signature against `attacker-org`'s own secret.
7. `StatusHandler#process` executes `Commit.where(sha: 'S')`, which matches the victim's tracked commit (since SHAs are globally unique identifiers, not scoped to a repository) and calls `create_status_from_github!`, writing a forged `success` status onto the victim's stack's commit — potentially satisfying `ci.require`/unblocking deploy gating for `victim-org/app` without ever touching `victim-org`'s webhook secret or credentials.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-27)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
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
      end
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

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/status.rb (L23-34)
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
    end
```
