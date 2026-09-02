### Title
Webhook signature verified against `repository.owner.login` while handlers act on `repository.full_name` — cross-organization stack sync/state corruption in multi-App deployments - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to check the HMAC signature against using `repository.owner.login` (falling back to `organization.login`), but every `Webhooks::Handlers::Handler` subclass resolves the repository/stack to act on using a *different* field of the same payload: `repository.full_name`. These two fields are never cross-validated against each other, so the "organization whose secret authenticated this delivery" and the "repository whose stack gets mutated" are two independently-controlled pieces of untrusted JSON, bound only by developer assumption, not by code.

### Finding Description
`verify_signature` picks the signing secret to validate against based on `repository.owner.login`: [1](#0-0) 

`GitHubApp#verify_webhook_signature` explicitly short-circuits to `true` when no `webhook_secret` is configured for that organization: [2](#0-1) 

This is a documented, supported configuration (`webhook_secret: nil`/blank is explicitly allowed, including in multi-org setups such as `test/dummy/config/secrets_double_github_app.yml`): [3](#0-2) [4](#0-3) 

Once signature verification passes, `create` dispatches the **entire raw JSON body** to every registered handler for the event, unmodified: [5](#0-4) 

Every handler resolves the target `Repository`/`Stack` using `repository.full_name`, a field that was never used or bound during signature verification: [6](#0-5) 

`PushHandler` then triggers a stack sync against an attacker-supplied `after` (head sha) for every un-archived stack whose branch matches: [7](#0-6) 

The equality the code implicitly (and incorrectly) assumes is:
`org that authenticated the signature (repository.owner.login)` == `repository that the handler mutates (repository.full_name)`

Nothing enforces this. In a Shipit deployment configured with multiple GitHub Apps (one per organization, as the engine explicitly supports via `Shipit.github(organization:)`), if **any** configured organization has no `webhook_secret` set, an attacker can submit a webhook whose `repository.owner.login`/`organization.login` names that unsecured organization (bypassing signature checks entirely, per the `return true unless webhook_secret` shortcut) while setting `repository.full_name` to a repository belonging to a *different, secured* organization. `verify_signature` passes because it only looked at `repository.owner.login`; the handler layer then operates on the unrelated `full_name` repository/stack.

### Impact Explanation
This lets an unauthenticated caller trigger `GithubSyncJob` (`stack.sync_github(expected_head_sha: <attacker value>)`) and other handler side effects (e.g. `check_suite`/`status`/`membership`/`pull_request` handlers, which also key off `repository.full_name`) against a stack whose real organization is properly signature-protected, purely by picking an org name with no configured secret. This is an authentication-boundary violation reachable by an unprivileged network attacker with no session, no API token, and no knowledge of any `webhook_secret` — it only requires that the target instance has at least one configured GitHub organization without a webhook secret, a state the engine explicitly documents as supported ("Webhook secret (optional)"). The blast radius is state corruption/synchronization forcing on stacks the attacker does not control (unauthorized sync triggering with attacker-influenced `expected_head_sha`), which can affect commit ingestion, lock/detach logic (`stack.lock_reverted_commits!`), and downstream deploy-pipeline state for a repository the attacker was never authorized to interact with.

### Likelihood Explanation
Requires: (1) at least one configured GitHub organization on the Shipit instance without a `webhook_secret` (a supported, common configuration for non-production or newly-added orgs), and (2) knowledge of a target stack's `repo_owner`/`repo_name` and branch, all of which are public GitHub metadata. No credentials, sessions, or secrets are required from the attacker. Likelihood is Medium, gated entirely on the operator's webhook_secret configuration choice for at least one org rather than on any code-level control.

### Recommendation
In `WebhooksController#verify_signature`, after successfully verifying the signature for `repository_owner`, additionally assert that the `repository.owner.login` used for verification equals the owner segment of `repository.full_name` (and, ideally, resolve the actual `Repository`/`Stack` via `Shipit.github(organization: ...)` bound to the *same* organization that produced the verified secret) before invoking any handler. Alternatively, pass the verified `repository_owner` value explicitly into the handler dispatch and have `Webhooks::Handlers::Handler#repository_name`/`#stacks` cross-check that the owner segment of `full_name` matches the verified owner, rejecting (422) any mismatch.

### Proof of Concept
1. Configure Shipit with two GitHub Apps: `SecureOrg` (with `webhook_secret` set) and `OpenOrg` (with `webhook_secret: nil`), as in `secrets_double_github_app.yml`.
2. `SecureOrg` owns a stack tracking `SecureOrg/critical-repo`, branch `main`.
3. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OpenOrg" },
    "full_name": "SecureOrg/critical-repo"
  }
}
```
No `X-Hub-Signature` is required to be valid, because `repository_owner` resolves to `OpenOrg`, whose `webhook_secret` is `nil`, so `verify_webhook_signature` returns `true` unconditionally (`app/controllers/shipit/webhooks_controller.rb` + `lib/shipit/github_app.rb:76-83`).
4. `Webhooks.for_event('push')` dispatches `PushHandler`, which resolves `stacks` via `Repository.from_github_repo_name('SecureOrg/critical-repo')` (`handler.rb:32-38`) and calls `stack.sync_github(expected_head_sha: '<attacker-chosen-sha>')` on the matching, un-archived, `main`-branch stack — a stack that belongs to the properly-secured `SecureOrg`, which the attacker never authenticated against.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-47)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
```

**File:** docs/setup.md (L26-30)
```markdown
  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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
