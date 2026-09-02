This confirms the exploit chain. The `StatusHandler` matches statuses purely by `Commit.where(sha: params.sha)` — a global lookup across all stacks, with no ownership check against the organization that authenticated the webhook. Combined with `Status#schedule_continuous_delivery` triggering `ContinuousDeliveryJob`, and `Stack#should_delay_continuous_delivery?` gating on status success, this is sufficient to write a spoofed status onto any stack's commit and potentially trigger an unauthorized deploy.

### Title
Webhook Signature Verification Uses Unverified `repository.owner.login` to Select Signing Org, Allowing Cross-Organization Status/Event Spoofing - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub organization's webhook secret to verify the HMAC signature against by reading `repository.owner.login` (or `organization.login`) directly out of the untrusted, not-yet-verified JSON body. The handler that subsequently acts on the payload (e.g. `StatusHandler`) uses a different field from the same untrusted body — the commit `sha` (global lookup) or `repository.full_name` — to decide which stack/commit to mutate. Because the field used to pick the verifying secret and the field used to decide what gets written are independent and both attacker-controlled, an attacker who controls (or is unauthenticated against) any GitHub organization configured in Shipit with no `webhook_secret` set can forge events that are “verified” yet act on any other organization's stacks and commits.

### Finding Description
`verify_signature` is a `before_action` that runs before `params` is parsed for use by handlers: [1](#0-0) 

The org used to select the verifying `GitHubApp` instance comes from the unverified body: [2](#0-1) 

`GitHubApp#verify_webhook_signature` explicitly treats an org with no configured `webhook_secret` as always valid, signature or not: [3](#0-2) 

This is a documented, supported configuration state — every example secrets file ships `webhook_secret: # nil`: [4](#0-3) [5](#0-4) 

Once `verify_signature` passes, `create` parses the same raw body and dispatches it to handlers keyed only by event type — with no re-check that the org selected for signature verification matches the repository/commit the handler is about to mutate: [6](#0-5) 

`StatusHandler` looks up commits **globally by `sha`**, with no scoping to the organization that was used to authenticate the request, and directly writes attacker-supplied `state`/`context`/`target_url`/`description` onto any matching commit across any stack: [7](#0-6) 

Writing a `Status` triggers continuous delivery evaluation directly: [8](#0-7) 

And `Stack#should_delay_continuous_delivery?`/`trigger_continuous_delivery` use the (now attacker-forged) status state to decide whether to deploy: [9](#0-8) [10](#0-9) 

**The broken binding, stated as an equality that should hold but doesn't:**
`organization(used to select verifying webhook_secret)` == `organization(that owns the repository/commit the payload writes to)`.

Because `repository_owner` (used only to pick the verifying `GitHubApp`) and the commit `sha`/`repository.full_name` (used by the handler to decide what to mutate) are two independent, attacker-controlled fields in the same unverified JSON body, this equality is never enforced. An attacker who is a member/admin of any org configured in Shipit with `webhook_secret` unset (a documented default) can set `repository.owner.login` to that org while setting `sha`/`repository.full_name` to point at a target org's commit/stack.

### Impact Explanation
This breaks the deployment-trust binding between "organization that authenticated the webhook" and "repository that gets written," matching the Critical impact of an unauthorized deploy: a forged `status` event can inject a `success` state for a required CI context on a target stack's commit, which `Status#schedule_continuous_delivery` and `Stack#trigger_continuous_delivery`/`should_delay_continuous_delivery?` use to gate and trigger automatic deployment for stacks with continuous deployment enabled — allowing an attacker with no access to the target organization or repository to cause code to be deployed based on a fabricated CI status. The same missing binding also lets an attacker spoof `push` (triggering `GithubSyncJob` sync attempts) or `pull_request`/`membership` events scoped to a stack/org they don't own.

### Likelihood Explanation
Any Shipit deployment supporting more than one GitHub organization (the documented multi-org config) is affected as soon as at least one configured org leaves `webhook_secret` unset — which is the default/example configuration shown in `config/secrets.development.example.yml` and `docs/setup.md`. No credentials, GitHub App installation, or Shipit session are required; the attacker only needs to know (a) that such an org exists in the target's Shipit config and (b) the target commit sha and stack's required CI context — both are public GitHub metadata.

### Recommendation
After verifying the HMAC signature, re-derive the organization that owns the actual repository being acted upon (e.g. via `repository.full_name` looked up against `Repository`/`Stack` records) and require it to match the organization whose secret validated the signature. Alternatively, scope `StatusHandler`'s `Commit.where(sha:)` lookup (and all other handlers relying on `Handler#repository_name`) to the same organization resolved during `verify_signature`, and reject the webhook if they diverge. Do not treat a missing `webhook_secret` as an implicit "always verified" for organizations other than the single-org legacy configuration.

### Proof of Concept
1. Configure Shipit with two orgs, `TrustedOrgWithNoSecret` (no `webhook_secret` set — the documented default) and `Victim` (has a stack tracking commit `abc123` with required CI context `ci/required`).
2. POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "TrustedOrgWithNoSecret" }, "full_name": "trusted/whatever" },
  "sha": "abc123",
  "state": "success",
  "context": "ci/required"
}
```
No `X-Hub-Signature` header is required — `verify_webhook_signature` in [11](#0-10)  returns `true` because `TrustedOrgWithNoSecret` has no `webhook_secret`.
3. `WebhooksController#create` dispatches to `StatusHandler`, which finds `Victim`'s commit `abc123` purely by `sha` ( [12](#0-11) ) and creates a `success` `Status` for it, with no check that `Victim` was the organization that authenticated the request.
4. If `Victim`'s stack has continuous deployment enabled and this was the last blocking status, `ContinuousDeliveryJob` deploys the commit automatically.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-30)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
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

**File:** app/models/shipit/stack.rb (L708-713)
```ruby
    def should_delay_continuous_delivery?(commit)
      commit.deploy_failed? ||
        (checks? && !EphemeralCommitChecks.new(commit).run.success?) ||
        !deployment_checks_passed? ||
        commit.recently_pushed?
    end
```
