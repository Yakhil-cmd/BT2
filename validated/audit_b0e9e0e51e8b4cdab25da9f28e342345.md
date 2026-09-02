### Title
Webhook signature verification keys off `repository.owner.login` while handlers act on `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App (and therefore the `webhook_secret` used to validate the HMAC) using `repository_owner`, read from `params.dig('repository', 'owner', 'login')` (or `organization.login`). The event handlers, however, resolve the `Stack`/`Repository` to act on using a completely different field of the same JSON body: `payload.dig('repository', 'full_name')`. Nothing enforces that the organization whose secret authenticated the request is the same organization that owns the repository the handler subsequently mutates.

### Finding Description
The controller's before_action performs the only authentication check on inbound webhooks: [1](#0-0) 

`repository_owner` is derived from attacker-controlled JSON: [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization config, and if that organization's `webhook_secret` is blank, `verify_webhook_signature` short-circuits to `true` regardless of the actual `X-Hub-Signature` header or payload content: [3](#0-2) 

Multi-organization Shipit deployments are an explicitly documented and supported configuration, where each organization key carries its own independent `webhook_secret` (some of which can legitimately be `nil`, e.g. during setup or for orgs that don't configure one): [4](#0-3) 

Once signature verification passes (trivially, for the org with no secret), `create` dispatches the entire raw JSON body to handlers unmodified: [5](#0-4) 

Handlers resolve the target `Repository`/`Stack` using `repository.full_name`, a field that was never covered or scoped by the signature check performed against `repository.owner.login`: [6](#0-5) 

For example, `PushHandler` triggers a `sync_github` (which enqueues `GithubSyncJob`, pulling and appending commits) for every non-archived stack whose branch matches, entirely driven by the unauthenticated `full_name`/`ref`/`after` fields: [7](#0-6) 

`StatusHandler` similarly writes a commit status for any commit matching an attacker-supplied `sha`, using an attacker-controlled `state`/`context`, which can influence deployability checks used to gate deploys/merges: [8](#0-7) 

This breaks the trust binding: `organization authenticated by verify_signature == organization owning the repository the handler writes to`. An attacker can craft a payload where `repository.owner.login` (or `organization.login`) names an organization configured in Shipit's `github:` secrets with no `webhook_secret` set, while `repository.full_name` names a real, tracked stack belonging to a different, secured organization. The signature check passes (because the secret-less org's check always returns `true`), yet the handler mutates state for the unrelated secured org's stack/commits.

### Impact Explanation
This allows an unauthenticated actor to forge GitHub webhook events (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.) for repositories belonging to an org that does have a properly configured `webhook_secret`, as long as any other organization configured in the same Shipit instance lacks one. Concretely this can: force a `sync_github` resync with an attacker-chosen `expected_head_sha`/`ref` on a tracked stack, and forge commit statuses (`StatusHandler`) that feed into deployability checks used by the merge queue / deploy gating logic — a path toward an unauthorized deploy or merge without any GitHub credential, API token, or Shipit session. This matches the report's core defect class: a value used for the trust/authorization decision (the org whose key signs — analogous to the "asset" being validated) is disjoint from the value the privileged operation actually acts on (the target repository — analogous to the drained token), exactly like the Sprinkler contract trusting the ETH sentinel address for pricing while lacking any binding that the "token" acted upon is the one that was verified.

### Likelihood Explanation
Exploitability is conditioned on the deployment having multiple organizations configured in `github:` secrets where at least one lacks a `webhook_secret` (a state the documented setup flow explicitly allows, and which is a plausible transient/misconfiguration state, e.g. during onboarding of an additional org). This is a real, if deployment-dependent, condition within the engine's own documented multi-org support rather than a hypothetical host misconfiguration outside the documented setup.

### Recommendation
Bind the signature-verifying organization to the repository actually acted upon: after selecting `repository_owner` for signature verification, re-derive/validate that `payload.dig('repository', 'full_name')`'s owner matches `repository_owner` before dispatching to handlers, and/or require `webhook_secret` to be present (reject with 422) for every configured organization rather than silently trusting unsigned payloads when `webhook_secret` is blank.

### Proof of Concept
1. Configure Shipit with two GitHub orgs in `secrets.github`: `orgA` (no `webhook_secret` set) and `orgB` (proper `webhook_secret`, with a tracked `Stack` for `orgB/target-repo`).
2. POST to `/webhooks` with header `X-Github-Event: push` and a body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/target-repo" }
}
```
No valid `X-Hub-Signature` for `orgB`'s secret is required — `verify_signature` selects `orgA`'s config, whose `verify_webhook_signature` returns `true` unconditionally per [9](#0-8) .
3. `PushHandler` resolves the stack via `full_name` = `orgB/target-repo` [6](#0-5)  and triggers `stack.sync_github(expected_head_sha: params.after)`, mutating state for `orgB`'s repository despite the request never being validated against `orgB`'s secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L182-209)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
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
```
