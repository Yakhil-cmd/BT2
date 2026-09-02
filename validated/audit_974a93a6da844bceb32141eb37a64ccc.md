### Title
Cross-organization webhook forgery via unbound `repository.owner.login`/`organization.login` signature selection - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization Shipit deployments, `WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to authenticate a webhook against using the attacker-controlled field `repository.owner.login` (or `organization.login`) taken from the *same, unauthenticated* request body. Once verified against that org's secret, the request body is dispatched unmodified to handlers, several of which (notably `StatusHandler`, but also `PushHandler`/`Handler#stacks`) act on a *different* field of the same payload (`repository.full_name`, or in `StatusHandler`'s case, no repository scoping at all, just `sha`) to decide which `Stack`/`Commit` to mutate. The org whose secret authenticated the request is never checked against the org/repo that is actually written to.

### Finding Description
`WebhooksController#verify_signature` picks the signing organization from attacker-supplied JSON: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization app config only when Shipit is configured in multi-org mode (`github_default_organization` non-nil, i.e. `secrets.github` is keyed by organization, as documented and exercised in `test/dummy/config/secrets_double_github_app.yml`): [3](#0-2) 

Signature verification itself is a pure HMAC check of the raw body against the secret of the *selected* org, with a documented bypass when that org has no secret configured (`webhook_secret: # nil` is explicitly shown as valid in `docs/setup.md` / `config/secrets.development.example.yml`): [4](#0-3) 

Once the signature check for the *attacker-chosen* organization passes, the identical JSON body is forwarded to every registered handler for the event: [5](#0-4) 

`Handler#stacks` resolves the target repository/stack from `repository.full_name`, a field completely independent of the one used for signature-org selection: [6](#0-5) 

`StatusHandler` is worse: it performs **no repository scoping at all** — it looks up commits globally by `sha` across the entire Shipit instance and writes a forged CI status to them: [7](#0-6) 

This breaks the intended equality binding **"organization authenticated == repository/stack written."** Concretely:
- Attacker controls (or is the legitimate GitHub org admin of) Org A, one of several organizations configured on a shared Shipit instance, and knows Org A's `webhook_secret` (or Org A has none configured, per the documented optional-secret configuration).
- Attacker POSTs to `/webhooks` with `X-Hub-Signature` computed using Org A's secret (or omitted if Org A's secret is blank), but with payload content (`sha`, `state`, `ref`, `after`, `repository.full_name`, etc.) referencing Org B's stack/commit.
- `verify_signature` selects Org A's `GitHubApp`, verifies successfully, and the forged event is then processed against Org B's data.

### Impact Explanation
Because `StatusHandler` (and by extension any commit matching the forged `sha`, instance-wide) accepts a forged `state`, an attacker with only access to one tenant organization on a shared Shipit instance can:
- Forge a `success`/`pending` CI status on any commit across any other organization's stack, which is used by `Commit#create_status_from_github!` → `Commit#add_status` to trigger `stack.schedule_merges` and mark the commit deployable: [8](#0-7) 

- This can enable an unauthorized merge/deploy of a commit that never actually passed CI in a victim organization's stack — a cross-tenant, cross-repository write of state that gates deploy eligibility — matching the "unauthorized deploy" / "cross-repository writes" impact tier.
- `PushHandler` similarly lets a forged event (authenticated as Org A) enqueue a `GithubSyncJob` against Org B's stack (resolved via `repository.full_name`), causing Shipit to fetch/append commits for a victim stack outside the authenticating organization's authority.

Severity is Medium-High depending on whether the deployment host is multi-tenant (multiple orgs configured under one Shipit instance, which the engine explicitly supports and documents), since the blast radius is bounded to instances that opt into multi-org configuration.

### Likelihood Explanation
Requires: (1) the Shipit instance to be configured with multiple GitHub organizations (a supported, documented configuration — see `test/dummy/config/secrets_double_github_app.yml` and the multi-org example in `config/secrets.development.example.yml`), and (2) the attacker to control or know the webhook secret of at least one of those configured organizations (or one configured with a blank secret, which the docs mark as "optional"). This is a realistic scenario for organizations that host a shared Shipit instance for multiple business units/teams with separate GitHub orgs — an unprivileged attacker relative to the victim org, but a legitimate webhook administrator of their own (lower-trust) org.

### Recommendation
Bind signature verification to the same field(s) used for handler dispatch, and vice versa:
1. Have `verify_signature` and each `Handler#stacks`/`repository_name` derive the organization/repository from the **same** payload field (e.g., always `repository.full_name`), rejecting requests where `repository.owner.login`/`organization.login` disagree with `repository.full_name`'s owner segment.
2. After selecting the GitHub App via `repository_owner`, re-verify that the resolved `Repository`/`Stack` for the event actually belongs to that same organization before any handler mutates state (especially in `StatusHandler`, which currently performs no repository check whatsoever).
3. Consider requiring `webhook_secret` to be present for any organization in multi-org mode, since a blank secret currently makes `verify_webhook_signature` always return `true` (`lib/shipit/github_app.rb:76-77`), amplifying the cross-org forgery to a fully unauthenticated one for that org's requests.

### Proof of Concept
Given a Shipit instance configured with two organizations, `OrgA` (attacker-controlled webhook secret) and `OrgB` (victim), and a `Shipit::Stack`/`Commit` belonging to `OrgB/victim-repo` with `sha=deadbeef`:

```
POST /webhooks HTTP/1.1
X-Github-Event: status
X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>
Content-Type: application/json

{
  "sha": "deadbeef",
  "state": "success",
  "context": "ci/forced",
  "description": "forged",
  "created_at": "2026-09-02T00:00:00Z",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```

`verify_signature` computes `repository_owner = "OrgA"`, loads `Shipit.github(organization: "OrgA")`, verifies the HMAC against `OrgA`'s secret (which the attacker legitimately knows) — succeeds. `StatusHandler#process` then runs `Commit.where(sha: "deadbeef").each { |c| c.create_status_from_github!(params) }` (no organization/repository check at all), forging a `success` status on the `OrgB` commit, which can trigger `stack.schedule_merges` / mark the commit deployable in `OrgB`'s stack. This is unverifiable end-to-end in this static review because it depends on runtime multi-org configuration and downstream deploy-gating logic (e.g., whether the victim stack's CD pipeline auto-deploys on `success`), which was not exhaustively traced beyond `Commit#add_status`.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-63)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
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

**File:** app/models/shipit/commit.rb (L365-386)
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
