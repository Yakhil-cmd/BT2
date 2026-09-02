### Title
Cross-organization webhook forgery via mismatched signature-verification identity and payload-processing identity - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate an inbound webhook against using `repository_owner`, a value read straight from the untrusted, unverified JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`). Every webhook `Handler` (subclass of `Shipit::Webhooks::Handlers::Handler`), however, resolves the target `Repository`/`Stack` using a *different* field of that same untrusted body: `payload.dig('repository','full_name')`. Nothing enforces that `repository.full_name`'s owner segment matches the `repository.owner.login`/`organization.login` used to select the verifying secret. This breaks the equality that should hold: `organization whose secret authenticated the request == organization that owns the repository being acted upon`.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb` computes the organization used to pick the verifying `GitHubApp`/secret entirely from attacker-suppliable JSON, before any signature check occurs: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` in multi-organization deployments (`Shipit.github_organizations` returning more than the default single entry) looks up a distinct, per-organization `webhook_secret` from `secrets.github[organization]`: [3](#0-2) 

Signature verification itself only proves the raw body was HMAC-signed with *that selected organization's* secret — it says nothing about which repository the payload claims to describe: [4](#0-3) 

Every webhook handler then independently re-reads the repository identity from the same untrusted body to decide **which Stack(s) to mutate**, using `repository.full_name` rather than the field used for signature selection: [5](#0-4) 

Concrete handlers that act on state using this unguarded `full_name` lookup include `PushHandler` (triggers `stack.sync_github`), `StatusHandler` (writes commit CI statuses that directly feed `Commit#deployable?`), and the pull-request handlers (archive/create/unarchive review stacks): [6](#0-5) [7](#0-6) [8](#0-7) 

**Broken binding (equality that should hold but doesn't):**
`organization authenticated by X-Hub-Signature` **==** `organization owning the repository the handler writes to`.

Before the attack: for a legitimate GitHub-originated webhook, `repository.owner.login` and `repository.full_name`'s owner segment are always consistent, because GitHub itself populates both fields from the same event source.

After the attacker's forged request: an entity that legitimately knows (or controls) the webhook secret for one configured organization (`OrgA` — e.g., an org admin who registered their own GitHub App/webhook per `docs/setup.md`'s multi-tenant flow) can construct an arbitrary raw JSON body themselves, setting `repository.owner.login`/`organization.login` = `OrgA` (so `verify_signature` computes a valid HMAC using the secret they know) while setting `repository.full_name` = `OrgB/some-repo` (any repository tracked by a *different* configured Shipit organization/tenant). The controller only checks the HMAC against the org derived from the owner field, then dispatches the full, attacker-chosen payload — including the mismatched `full_name` — to the handlers.

### Impact Explanation
This lets an attacker who is only privileged within their own (lower-trust) organization's GitHub App forge events attributed to unrelated repositories/stacks belonging to other organizations configured in the same Shipit instance:
- `push` events → force `GithubSyncJob`/`stack.sync_github` on a foreign stack.
- `status` events → inject a fabricated `success` commit status on a target stack's commit via `StatusHandler` → `Commit#create_status_from_github!`, directly flips `Commit#deployable?` to true, which can bypass CI gating and enable an **unauthorized deploy** of a commit that never actually passed CI on the target repository.
- `pull_request` events → archive/unarchive/create review stacks belonging to a foreign repository.
- `membership` events (per `WebhooksController` test suite) → create/delete `Team`/`User`/`Membership` records that feed `Shipit.github_teams` authorization checks used by `User#authorized?`.

This crosses the "escalation into `Shipit.github_teams` authorization" and "unauthorized deploy" thresholds defined as in-scope High/Critical impacts.

### Likelihood Explanation
Exploitability requires the attacker to already hold a webhook secret for at least one organization configured in the Shipit instance. In the documented single-app setup this is a Shipit-admin-controlled secret and not attacker-reachable, so the bug is not exploitable there. It becomes concretely exploitable specifically in the self-service, multi-organization configuration mode (`Shipit.github_organizations`, per-org `secrets.github[org]` entries, each with an independently configured `webhook_secret`/GitHub App the org's own admin sets up) — a deployment pattern the engine explicitly supports via `github_app_config`/`github_organizations`. In that mode, any onboarded organization's administrator (an "unprivileged" actor with respect to every other tenant) can trivially exploit this because they legitimately know their own secret and full control over the raw payload they send.

### Recommendation
After signature verification succeeds, require that the organization used to select the verifying secret match the owner segment of `repository.full_name` (and `organization.login` for org-scoped events) before dispatching to handlers; reject the webhook otherwise. Alternatively, have each `Handler` scope its `Repository`/`Stack` lookup by the verified organization rather than trusting the raw payload's `full_name` field independently.

### Proof of Concept
1. Configure Shipit in multi-organization mode with two tenants, `OrgA` (attacker-administered GitHub App, secret `S_A`) and `OrgB` (victim tenant, has a tracked `Stack` for `OrgB/secret-repo`).
2. Attacker crafts a raw JSON body:
```json
{
  "sha": "<target commit sha on OrgB/secret-repo>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "full_name": "OrgB/secret-repo", "owner": { "login": "OrgA" } }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(S_A, body)>` using their own known `OrgA` secret, and sets `X-Github-Event: status`.
4. POST to `/webhooks`. `WebhooksController#verify_signature` computes `repository_owner == "OrgA"`, loads `Shipit.github(organization: "OrgA")`, and the signature validates successfully against `S_A`.
5. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which locates the commit by `sha` (global, not org-scoped) and calls `commit.create_status_from_github!`, injecting a forged "success" CI status for `OrgB`'s commit — flipping `Commit#deployable?` to true regardless of real CI state on `OrgB/secret-repo`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```
