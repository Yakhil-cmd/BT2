### Title
Webhook signature is verified against the payload's claimed organization, but state-changing handlers write to commits/stacks with no matching organization/repository check - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/`webhook_secret` to validate the HMAC signature against using an organization string taken from the same untrusted JSON body it's about to validate. Once "verified," the event is dispatched to handlers (e.g. `StatusHandler`) that mutate state without re-checking that the record they write to actually belongs to that organization. This breaks the binding "organization that authenticated" == "repository/commit that is written," letting a party who controls (or knows the secret of) *one* Shipit-configured GitHub organization forge webhook events that mutate commits/stacks belonging to a *different* tracked organization/repository.

### Finding Description
`verify_signature` derives the signing organization purely from the payload, then verifies against that organization's app: [1](#0-0) [2](#0-1) 

`Shipit` explicitly supports hosting multiple independent GitHub organizations from a single instance, each with its own `webhook_secret` supplied by that organization's own App admin: [3](#0-2) [4](#0-3) 

`GitHubApp#verify_webhook_signature` also returns `true` unconditionally when no `webhook_secret` is configured for that organization (a documented "optional" setting): [5](#0-4) 

Once the request passes `verify_signature` (using Org A's secret, or no secret at all), `WebhooksController#create` dispatches the event to handlers with the raw, attacker-controlled JSON: [6](#0-5) 

Critically, `StatusHandler` — which creates a CI status for a commit and can trigger deploys — looks up the target purely by `sha`, with **no scoping to a repository or organization at all**: [7](#0-6) 

Creating a status can immediately move a commit to `success`/`pending`, which schedules merges and (for continuously-deployed stacks) real deploys: [8](#0-7) 

So the equality that should hold — "organization whose secret authenticated this request" == "organization/repository whose commit is mutated" — is never enforced. Only `repository_owner` is used to pick a secret; the actual mutation target (`Commit.where(sha: params.sha)`) is entirely decoupled from it.

### Impact Explanation
An attacker who administers or otherwise knows the webhook secret for **any one** GitHub organization configured on a shared Shipit instance (a supported, documented multi-tenant configuration), or who targets an organization whose `webhook_secret` is left unset (documented as optional), can pass `verify_signature` and then submit a forged `status` event containing an arbitrary `sha` belonging to a commit tracked under a completely different organization's stack. This forges a CI status for that commit, which can flip it to `success`, triggering `stack.schedule_merges` (unauthorized merge) or continuous-deployment auto-deploy (unauthorized deploy) on a repository/stack the attacker has no legitimate access to — satisfying the "unauthorized deploy, rollback or merge" / cross-repository-write impact bar, without any Shipit session, `ApiClient` token, or the victim organization's own webhook secret.

### Likelihood Explanation
The `/webhooks` endpoint is unauthenticated by design (it's meant to receive external GitHub callbacks) and is reachable by anyone who can send an HTTP POST. The only gate is `verify_webhook_signature`, whose secret selection is driven entirely by attacker-controlled JSON fields (`repository.owner.login` / `organization.login`). Multi-organization Shipit deployments and optional webhook secrets are both explicitly documented, first-class configurations, so exploitation does not require deviating from the documented deployment model — only that the attacker controls or knows the secret for at least one organization configured on the shared instance (or targets one with no secret set).

### Recommendation
Bind webhook authentication to the resource being mutated, not just to a claimed field in the payload:
- After verifying the signature for organization X, require that every entity the handler subsequently reads/writes (repository, stack, commit) actually belongs to organization X, e.g. by having `Handler#stacks`/`StatusHandler#process` filter through `repository.owner` == the verified organization.
- Do not allow `verify_webhook_signature` to silently return `true` when `webhook_secret` is blank in multi-organization mode; require an explicit, secure default (reject or warn loudly) instead of treating "unconfigured secret" as "always valid."
- Consider scoping `StatusHandler`'s `Commit.where(sha: params.sha)` lookup to commits belonging to stacks whose repository matches `payload.dig('repository', 'full_name')` and the authenticated organization, closing the sha-only global match.

### Proof of Concept
1. Operate a Shipit instance configured for two GitHub orgs, `OrgA` and `OrgB` (per `docs/setup.md`'s "Using Multiple Github Applications"), where the attacker administers `OrgA`'s GitHub App (and thus knows `OrgA`'s `webhook_secret`, or `OrgA` was configured with no secret at all).
2. Attacker crafts a `status` event payload:
```json
{
  "sha": "<sha of a commit belonging to a stack under OrgB>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/attacker-repo" }
}
```
3. Attacker computes `X-Hub-Signature` using `OrgA`'s known secret (or omits it if `OrgA` has none) and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")` and successfully verifies the signature (per `app/controllers/shipit/webhooks_controller.rb:24-30`).
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` (per `app/models/shipit/webhooks/handlers/status_handler.rb:20-24`), finds the OrgB commit purely by `sha`, and calls `create_status_from_github!`, which can flip the commit to `success` and trigger `stack.schedule_merges` / continuous deployment for `OrgB`'s stack — despite the request only ever being authenticated as `OrgA`.

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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
