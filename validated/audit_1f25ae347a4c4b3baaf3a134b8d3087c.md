### Title
Webhook signature verification keyed on `repository.owner.login` while handlers act on the unrelated `sha` / `repository.full_name` field, allowing cross-repository status injection - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
This is the closest analog to the "argmax" bug class in this engine: a value used to select/validate a trust decision (which organization's secret verifies the HMAC signature) is decoupled from the value the handler actually consumes to mutate state (the commit `sha` / `repository.full_name`). Just as `blockOfMaxPower` was updated while `highestVotingPower` was left stale — breaking the equality between "the block selected" and "the voting power backing that selection" — here the equality that should hold is: `organization whose secret verified this payload == organization owning the repository/commit the handler writes to`. That equality is never enforced.

### Finding Description
`WebhooksController#verify_signature` selects a `GitHubApp` (and its `webhook_secret`) using only `repository_owner`, derived from `params.dig('repository','owner','login')`, and calls `verify_webhook_signature` against the *entire* raw payload: [1](#0-0) 

`GitHubApp#verify_webhook_signature` trivially returns `true` when that organization has no `webhook_secret` configured: [2](#0-1) 

In multi-org deployments (documented as a first-class configuration mode), each organization has its own independent `webhook_secret`: [3](#0-2) 

Because `GithubHook`/`GitHubApp` configuration is looked up purely by the organization name embedded in the payload's `repository.owner.login`, and the signature is verified against *that* organization's secret only, any organization in the fleet that has `webhook_secret: nil` (a supported, explicitly-documented configuration state — see `config/secrets.development.shopify.yml` and `test/dummy/config/secrets_double_github_app.yml`) becomes a "signature-free" entry point. An attacker who knows (or guesses) the name of any such unsecured organization can submit a `status` webhook claiming `repository.owner.login` = that unsecured org while the actual `sha` field references a commit belonging to a *different, secured* stack: [4](#0-3) 

`StatusHandler#process` looks up commits **globally by `sha`** — with no scoping to the organization that was actually authenticated: [5](#0-4) 

So the binding that should be enforced ("the org whose secret verified this request" == "the org/repo whose commit gets a new status") is broken: verification is scoped to `repository.owner.login`, while the actual mutation (`Commit.where(sha: params.sha)`) is scoped to nothing at all — it can hit any commit in the database regardless of which organization it belongs to.

### Impact Explanation
An unprivileged external attacker who can reach the `/webhooks` endpoint can forge a `status` (or similarly commit-sha-keyed) event for any commit SHA in the system, as long as they can name one configured organization that has no webhook secret set (a state the project's own example configs and multi-org docs show as valid/expected). This lets them inject arbitrary CI status updates (`state`, `context`, `description`, `target_url`) onto commits belonging to stacks under *other, properly-secured* organizations. Because commit status transitions drive `Commit#add_status`, which can trigger `ProcessMergeRequestsJob` and continuous-deployment scheduling (`stack.schedule_merges`), a forged "success" status can cause an unauthorized merge-queue advance or trigger an unauthorized deploy — matching the "unauthorized deploy or merge" High-severity criterion.

### Likelihood Explanation
Requires only knowledge of an organization name lacking a `webhook_secret` in a multi-org Shipit deployment — no GitHub credentials, API tokens, or repository write access are needed, since the endpoint is unauthenticated apart from the (bypassable) HMAC check. This is a plausible operational configuration explicitly documented and shown in the codebase's own example secrets files, making the likelihood non-trivial in any fleet running the documented "Using Multiple GitHub Applications" mode where not every org enrolls a webhook secret.

### Recommendation
Enforce the binding explicitly: after verifying the signature for `repository_owner`, additionally check that the commit(s)/stacks acted upon by the handler actually belong to that same verified `repository_owner`/`repository.full_name`, rather than resolving commits/stacks globally by `sha`. Alternatively, require (and fail closed when missing) a `webhook_secret` for every configured organization so `verify_webhook_signature` can never trivially pass, and have handlers cross-check `params.dig('repository','full_name')` against the resolved commit's stack before mutating anything.

### Proof of Concept
1. Configure Shipit in multi-org mode with `OrgA` (has `webhook_secret` set, owns stack `OrgA/app`) and `OrgB` (no `webhook_secret` configured — a state shown valid in `test/dummy/config/secrets_double_github_app.yml`).
2. Attacker sends `POST /webhooks` with header `X-Github-Event: status` and body:
   ```json
   {
     "repository": {"owner": {"login": "OrgB"}, "full_name": "OrgB/whatever"},
     "sha": "<sha of a commit belonging to OrgA/app>",
     "state": "success",
     "context": "ci/forged"
   }
   ```
   No `X-Hub-Signature` header is required to match anything, because `Shipit.github(organization: 'OrgB').verify_webhook_signature` returns `true` unconditionally (no secret configured for `OrgB`).
3. `WebhooksController#verify_signature` passes; `Shipit::Webhooks::Handlers::StatusHandler#process` runs `Commit.where(sha: params.sha)` and applies the forged status to the `OrgA/app` commit, potentially advancing its merge queue or triggering continuous deployment — despite the attacker never having presented any credential valid for `OrgA`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
