### Title
Cross-repository commit status forgery via unscoped `StatusHandler` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
The webhook signature in `WebhooksController#verify_signature` is verified against the GitHub organization derived from the payload's `repository.owner.login` (or `organization.login`), but the `status` event handler that actually mutates state ignores the repository entirely and updates every `Commit` row in the database whose `sha` matches, regardless of which stack/repository it belongs to. This breaks the binding "the organization that authenticated == the repository that is written."

### Finding Description
`WebhooksController#verify_signature` selects the GithubApp config (and therefore the webhook secret) to check the HMAC signature against, based on `repository_owner`, which is read directly from the untrusted JSON payload: [1](#0-0) [2](#0-1) 

Once the signature check for that organization succeeds, the whole payload is dispatched to the matching event handler: [3](#0-2) 

For the `status` event, `StatusHandler#process` looks up commits solely by `sha`, with no scoping to the repository/stack that the verified webhook secret belongs to: [4](#0-3) 

`Commit` rows are only uniquely indexed per `(stack_id, sha)` — the same `sha` can legitimately exist across many different stacks/repositories (e.g. mirrored repos, forks, or commits with identical tree/author/committer/timestamp content, which are fully attacker-reproducible in a repository the attacker controls), as evidenced by the migration `db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb`. Because `StatusHandler` does not filter by `Repository.from_github_repo_name(repository_name)` (unlike every other handler such as `PushHandler`, which does use `stacks` scoped to the payload's `repository.full_name`): [5](#0-4) [6](#0-5) 

an attacker who controls a repository that has the Shipit GitHub App installed (and thus can trigger a genuine, correctly-signed `status` webhook for their own org) can forge a commit in their own repository with byte-identical git object content (same tree, parent, author, committer, message, timestamps) to a commit tracked in a victim stack belonging to a different organization, producing the identical SHA-1. Sending (or having GitHub send) a `status` event for that sha — correctly signed with the attacker's own org's webhook secret — will be accepted by `verify_signature` (because it only checks the attacker's own org), and then `StatusHandler` will apply the forged status (`success`/`failure`) to the matching `Commit` row in the *victim's* stack, since the lookup is entirely unscoped.

### Impact Explanation
Commit statuses drive deploy-readiness gating in `Stack#deployable_commits`/`Commit#deployable?` via `required_statuses`/`blocking_statuses`. Forging a `success` status on a victim's commit that never actually passed CI can unblock and enable an **unauthorized deploy** on that victim's stack — one of the explicitly listed Critical impacts (unauthorized deploy). This crosses an organization/repository trust boundary without requiring any Shipit session, API token, or write access to the victim's repository — only a legitimate GitHub App installation on any org configured in the same Shipit instance.

### Likelihood Explanation
Exploitation requires: (1) the attacker's own org/repo to have the Shipit GitHub App installed (a normal, unprivileged tenant of a multi-org Shipit deployment), and (2) the ability to reproduce an identical git commit object (fully attacker-controlled, since git commit content, including author/committer timestamps, is fully specifiable) to obtain a matching SHA-1 with a target commit in another tracked stack. This is a deterministic, reproducible technique (not a brute-force SHA-1 collision) usable whenever the victim's target commit content is known/public, which is common for open-source or cross-mirrored repositories. This makes the likelihood moderate-to-high in any multi-tenant Shipit installation.

### Recommendation
Scope `StatusHandler#process` (and any other handler that queries by `sha` alone) to the repository resolved from the verified webhook's payload, mirroring the pattern used in `Handler#stacks`/`PushHandler`, e.g. `stacks.joins(:commits).where(commits: { sha: params.sha })` or equivalently filter `Commit.where(sha: params.sha, stack_id: stacks.pluck(:id))`, instead of matching `sha` across the whole `commits` table.

### Proof of Concept
1. Attacker controls `attacker-org/repo`, which has the Shipit GitHub App installed with webhook secret `S_A`.
2. Victim stack tracks `victim-org/repo`, with a public commit `C` (sha `deadbeef...`) that has not passed CI (status `pending`/`failure`).
3. Attacker creates an empty repository and cherry-picks/replays commit `C`'s exact tree, parent, author, committer, and message/timestamps into it — producing an identical SHA-1 `deadbeef...` in their own repo (verifiable locally with `git cat-file -p` / `git commit-tree` reproduction).
4. Attacker triggers (or GitHub's normal CI integration triggers) a `status` webhook event for `attacker-org/repo` with `sha=deadbeef...`, `state=success`, correctly HMAC-signed with `S_A`.
5. `WebhooksController#verify_signature` resolves `repository_owner = "attacker-org"`, fetches `S_A`, and verification succeeds.
6. `StatusHandler#process` runs `Commit.where(sha: "deadbeef...")`, which returns **both** the attacker's own commit row and the victim's commit `C`, and calls `create_status_from_github!` on each — marking the victim's commit `success` and potentially unblocking an unauthorized deploy on `victim-org/repo`'s stack.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
