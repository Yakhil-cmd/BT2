This confirms the vulnerability chain. Let me finalize my analysis with the key evidence already gathered.

The critical binding break is confirmed:
- `WebhooksController#verify_signature` selects which `GitHubApp`/secret to validate against using `repository_owner`, which is read straight from the untrusted JSON body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`) *before* the signature check occurs.
- The handlers (`PushHandler`, `StatusHandler`, `Handler#repository_name`, `PullRequest` handlers) resolve the actual `Repository`/`Stack` to act on using a **different** field from the same payload: `repository.full_name`.
- Because HMAC verification only proves "this body was signed with the secret belonging to whatever org name is embedded in the body," and does not verify that `repository.full_name`'s owner matches that same org, an attacker who legitimately controls one configured GitHub App/org in Shipit's multi-org config (and thus knows its `webhook_secret`) can forge a signed payload whose `repository.owner.login`/`organization.login` is their own org (so the correct secret is selected and validated) while `repository.full_name` names a completely different repository belonging to another org that Shipit also manages. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

### Title
Webhook signature is validated against the org name embedded in the payload while handlers act on a different, unverified repository field, allowing cross-organization forged CI status/push events - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` derives which GitHub App configuration (and therefore which `webhook_secret`) to validate the request's `X-Hub-Signature` against using `repository_owner`, a value taken directly from the still-unauthenticated JSON body. Once the signature is accepted, the event is dispatched to handlers (`PushHandler`, `StatusHandler`, the `PullRequest` handlers) that resolve the target `Repository`/`Stack` using a *different* field in the same body: `repository.full_name`. Nothing ties these two fields together, so a valid signature proves only that the request was signed with the secret for whatever organization name is present in the body — not that the repository being acted upon belongs to that organization.

### Finding Description
`verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` (or the `organization.login` fallback) before any cryptographic check, then calls `Shipit.github(organization: repository_owner)` to obtain that org's `GitHubApp` and validates the raw body against that org's `webhook_secret`: [7](#0-6) 

The handler base class (and concrete handlers like `PushHandler`/`StatusHandler`/the pull-request handlers) instead resolve the affected repository/stack from `repository.full_name`: [2](#0-1) 

Shipit explicitly supports hosting multiple independent GitHub organizations, each with its own App/secret, in the same instance (`docs/setup.md`, "Using Multiple Github Applications"). An operator (or a legitimate but malicious tenant) who controls one configured org's GitHub App knows that org's `webhook_secret` (they set it when installing the app). Nothing prevents them from crafting an arbitrary payload with:
- `repository.owner.login` = their own org name (so `verify_signature` selects their own known secret and the signature check passes), and
- `repository.full_name` = `"other-org/other-repo"` — a repository tracked under a completely different, unrelated organization also configured in the same Shipit instance.

The equality that should hold, `organization authenticated by the signature == organization owning the repository the handler mutates`, is broken: the signature only authenticates the org name string embedded in the JSON, and that string is never cross-checked against `repository.full_name`'s owner.

### Impact Explanation
This breaks the credential/organization boundary between tenants of a single multi-org Shipit deployment. Concretely:
- A forged `status` event can create a fake `success` CI status for an arbitrary commit belonging to a *different* org's tracked stack, and this status update can trigger continuous delivery (`add_status` → `schedule_merges`/`deployable_status` hook → `ContinuousDeliveryJob` → `trigger_continuous_delivery` → `trigger_deploy`), i.e. an **unauthorized deploy** of a stack the attacker has no legitimate relationship with. [5](#0-4) [6](#0-5) 
- A forged `push` event can force `GithubSyncJob`/`sync_github` to run against another org's stack using an attacker-chosen `after` SHA. [4](#0-3) 
- Pull-request webhook handlers similarly key off `repository.full_name` to create/archive review stacks or merge pull requests in a repository unrelated to the authenticating org.

This matches the "unauthorized deploy" High-impact category.

### Likelihood Explanation
Exploitation requires the attacker to be a legitimate operator of at least one GitHub organization/App configured in the same Shipit instance's multi-org `github:` secrets block (a supported, documented configuration), and to know their own `webhook_secret` — which they necessarily do, since they set it themselves during GitHub App creation. No access to any other tenant's secret, session, or `ApiClient` token is required. This is a realistic scenario for shared/multi-tenant Shipit deployments serving several organizations.

### Recommendation
Cross-validate that the organization used to select the webhook secret matches the owner embedded in the `repository.full_name` (or `organization.login`) actually being acted upon, before dispatching to handlers — e.g., reject the webhook if `repository.owner.login` does not match the leading path segment of `repository.full_name`, or better, look up the `Repository`/`Stack` first and verify its configured GitHub organization equals the one whose secret validated the signature.

### Proof of Concept
1. Operate a legitimate GitHub organization `attacker-org` that is configured as one of the multiple orgs in Shipit's `github:` secrets, with known `webhook_secret = S`.
2. Craft a JSON body for the `status` event:
```json
{
  "sha": "<victim commit sha tracked under other-org/other-repo>",
  "state": "success",
  "context": "ci/circleci",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "other-org/other-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(S, body)>` and send `POST /webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner = "attacker-org"`, fetches `attacker-org`'s `GitHubApp`, and validates the signature successfully using `S`.
5. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` — matching commits under `other-org/other-repo`'s stack — and calls `create_status_from_github!`, marking the commit as passing CI, potentially triggering `ContinuousDeliveryJob` and an unauthorized deploy for `other-org`'s stack, despite the attacker having no relationship with `other-org`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
  end
end
```

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```
