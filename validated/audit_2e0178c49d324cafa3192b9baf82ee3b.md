This confirms the exploitable path: `StatusHandler#process` locates commits purely by `sha` (`Commit.where(sha: params.sha)`, with **no repository/stack scoping**), and creating a `success` status can flip `Commit#deployable?` and trigger continuous deployment via `Status#schedule_continuous_delivery` / `add_status`'s `stack.schedule_merges`. [1](#0-0) [2](#0-1) [3](#0-2) 

### Title
Signature verification binds to `repository.owner.login`, not to `repository.full_name` acted on by handlers, enabling cross-organization webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to use for HMAC verification based on `repository_owner`, a value read directly from the untrusted JSON body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`). However, none of the event handlers that subsequently act on the payload are restricted to that same organization: `Handler#stacks`/`#repository_name` instead reads `payload.dig('repository', 'full_name')`, and `StatusHandler#process` doesn't even use the repository at all — it looks up commits globally by `sha`. This breaks the intended equality: "the organization whose secret validated the signature" == "the repository/stack that the handler acts on."

### Finding Description
`repository_owner` is used only to pick the `GitHubApp` instance (and thus the HMAC `webhook_secret`) for verifying `X-Hub-Signature`: [4](#0-3) 

Nothing ties the verified `repository.owner.login` to the `repository.full_name` (or `sha`) that downstream handlers use to decide which Shipit `Stack`/`Commit` to mutate: [5](#0-4) [6](#0-5) 

An attacker who legitimately administers **any one** GitHub organization onboarded onto this Shipit instance (i.e., one that has its own GitHub App/webhook secret configured, as documented for multi-org installs) knows that org's `webhook_secret` because they configured the GitHub App webhook themselves: [7](#0-6) 

They can then craft an arbitrary JSON body containing `repository.owner.login` (or `organization.login`) set to *their own* org — so `Shipit.github(organization: repository_owner).verify_webhook_signature` succeeds using a secret they legitimately possess — while embedding a completely different, victim `repository.full_name` and/or `sha` fields that are actually consumed by the handler logic. Because `verify_webhook_signature` only checks the HMAC of the raw body against the secret selected via the attacker-controlled `repository_owner` field, and the handlers never re-validate that `repository.full_name` belongs to the same organization used for verification, the forged event is accepted and dispatched against the victim stack.

`StatusHandler` is the most direct exploit: it doesn't reference `repository` at all, matching purely on global `sha`: [1](#0-0) 

This directly feeds `Commit#create_status_from_github!` → `add_status`, which can flip a commit's deployable state and trigger `stack.schedule_merges` / continuous delivery for the victim stack: [8](#0-7) 

### Impact Explanation
An attacker controlling one onboarded organization's webhook secret can forge signed webhook deliveries whose `repository`/`sha` claim to belong to a different, victim organization's stack. Via `StatusHandler`, this allows fabricating a `success` CI status for an arbitrary victim `sha`, which can flip `Commit#deployable?` and trigger continuous deployment (`stack.schedule_merges`, `schedule_continuous_delivery`), i.e., an **unauthorized deploy** on a repository the attacker never has real GitHub access to. This crosses the "unauthorized deploy" boundary called out in scope.

### Likelihood Explanation
Requires only that the attacker be a legitimate admin/owner of one GitHub organization that has been onboarded to the shared Shipit instance (documented as a normal multi-org configuration) — no privileged Shipit account, `ApiClient` token, or `GITHUB_TOKEN` is needed. The attack is a single crafted POST to `/webhooks` with a valid HMAC computed from a secret the attacker legitimately owns.

### Recommendation
Bind the verified `repository_owner`/organization used for signature verification to the repository the handler actually operates on: after verifying the signature, re-derive (or pass through) the authenticated organization and require that `payload.dig('repository', 'full_name')` (and any `sha` lookups) belong to a repository owned by that same organization before dispatching to handlers. For `StatusHandler` specifically, scope the `Commit` lookup by `stack.repository`'s owning organization rather than a bare global `sha` match.

### Proof of Concept
1. Onboard/administer GitHub org `attacker-org` on the shared Shipit instance; note its configured `webhook_secret` (self-supplied when creating the GitHub App).
2. Craft a `status` event JSON body: `{"repository": {"owner": {"login": "attacker-org"}}, "sha": "<victim-commit-sha>", "state": "success", ...}`.
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(webhook_secret_attacker_org, raw_body)>`.
4. POST to `/webhooks` with `X-Github-Event: status`. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and the signature validates.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the victim commit (belonging to a stack in a completely different organization), and calls `create_status_from_github!`, potentially flipping it to deployable/triggering continuous deployment.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
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
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/commit.rb (L366-384)
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

**File:** docs/setup.md (L181-209)
```markdown

### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```
