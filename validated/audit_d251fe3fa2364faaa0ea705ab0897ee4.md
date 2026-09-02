### Title
Cross-tenant webhook forgery: signature is verified against the payload's `repository.owner.login`/`organization.login`, but handlers act on the independently-controlled `repository.full_name` / `sha` fields — allowing an operator of one onboarded GitHub organization to inject fake CI statuses and force syncs on another organization's stacks - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which tenant's GitHub App/secret to validate the incoming webhook against using `repository_owner`, computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) . Once verification passes, the raw JSON body is dispatched unmodified to event handlers [2](#0-1) , which independently derive the target repository/commit from a *different* field of the same payload: `Handler#repository_name` reads `payload.dig('repository', 'full_name')` [3](#0-2) , and `StatusHandler` matches purely on `params.sha` across the entire `Commit` table with no repository/organization scoping at all [4](#0-3) . Nothing cross-checks that `repository.owner.login` (the field that selected the verification secret) is consistent with `repository.full_name` or with the SHA's actual owning stack.

Shipit is explicitly a multi-tenant engine: `Shipit.github(organization:)` looks up a per-organization config keyed by organization name in `secrets.github` [5](#0-4) , and each organization can have its own independently configured (and optionally blank) `webhook_secret` [6](#0-5) . This is the equivalent of the "USDM locked" binding-mismatch class: the engine authenticates against one identity (the organization named in the payload) but the code that actually writes state trusts a *different, unbound* field of the same, otherwise-unrelated payload.

### Finding Description
1. An attacker who legitimately controls (or has been granted webhook credentials for) **Org A**, which is one of several organizations onboarded onto the shared Shipit instance, can construct a webhook body where `repository.owner.login` (or `organization.login` for membership events) is `"OrgA"`, but `repository.full_name` is set to `"OrgB/some-other-repo"` (a stack that belongs to a completely different, unrelated tenant).
2. `verify_signature` computes `repository_owner = "OrgA"`, fetches Org A's `GitHubApp`, and verifies the HMAC using **Org A's own webhook secret** — which the attacker legitimately possesses for their own org's GitHub App [7](#0-6) .
3. Since the signature is valid for Org A, the request is accepted and the full JSON payload — including the attacker-controlled `full_name`/`sha` fields — is handed to the registered handlers [2](#0-1) .
4. `PushHandler` resolves the target stacks purely from `repository.full_name` [8](#0-7) [3](#0-2) , triggering `GithubSyncJob` for Org B's stack, unrelated to the org whose secret authorized the request.
5. `StatusHandler` is worse: it does not scope by repository at all, matching **any** `Commit` in the whole database sharing the given `sha` [4](#0-3) , and calls `commit.create_status_from_github!(params)`, which writes an attacker-chosen `state`/`context`/`description` as a CI status on that commit regardless of which organization's secret was used to authenticate the request.

The binding broken, expressed as an equality that fails:
`organization authenticated by webhook signature (repository.owner.login → Org A's secret)` ≠ `repository/commit actually mutated (repository.full_name / sha, unconstrained, cross-tenant)`.

### Impact Explanation
This is a cross-repository/cross-tenant write: a party with legitimate credentials for one onboarded organization (Org A) can forge CI status ("success") on commits belonging to any other organization's stack (Org B), including stacks with merge-queue or continuous-deployment rules that gate merges/deploys on CI status transitioning to `success` (per `Commit#create_status_from_github!` firing `deployable_status`/`ProcessMergeRequestsJob`, as exercised in `test/models/commits_test.rb`). Faking a passing status on an arbitrary commit can move that commit through the merge queue or trigger continuous deployment for a stack the attacker has no authorization over — matching the Critical bar of "unauthorized deploy, rollback or merge." It can also force resyncs on unrelated organizations' stacks via `PushHandler`, at minimum a cross-tenant integrity violation.

### Likelihood Explanation
Exploitability depends on the deployment actually hosting multiple organizations with independently held webhook secrets (the multi-tenant `Shipit.github(organization:)` model demonstrated in `secrets_double_github_app.yml` and `shipit_test.rb`). If only a single organization is configured, this degenerates to a same-tenant issue. In any genuinely multi-tenant deployment (the scenario the engine's own config format explicitly supports), any organization's legitimate GitHub App owner can exploit this against every other tenant sharing the same Shipit instance — no `ApiClient` token, GitHub App private key, or Shipit session is required, only the target's already-known secret for their *own* org.

### Recommendation
Cross-validate the organization used to select/verify the webhook signature against the organization embedded in the fields the handlers actually act on (`repository.full_name`'s owner segment, or the owning stack's configured GitHub organization) before dispatching to handlers. `StatusHandler` in particular must scope `Commit.where(sha: ...)` to commits belonging to stacks whose repository owner matches the verified `repository_owner`, not to all commits system-wide.

### Proof of Concept
1. Deployment hosts two organizations, `OrgA` and `OrgB`, each with its own GitHub App and `webhook_secret` (per `test/dummy/config/secrets_double_github_app.yml` pattern).
2. Attacker, who administers `OrgA`'s GitHub App, knows `OrgA`'s webhook secret.
3. Attacker crafts a `status` event payload:
```json
{
  "sha": "<sha of a commit belonging to OrgB's stack>",
  "state": "success",
  "context": "ci/travis",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/target-repo" }
}
```
4. Attacker computes `X-Hub-Signature` using `OrgA`'s own webhook secret and POSTs to `/webhooks`.
5. `verify_signature` resolves `repository_owner = "OrgA"`, fetches `OrgA`'s `GitHubApp`, and the signature verifies successfully (`app/controllers/shipit/webhooks_controller.rb:24-30`).
6. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which finds the commit purely by `sha` (no org check) and calls `create_status_from_github!`, writing a forged `success` status onto `OrgB`'s commit — potentially unblocking `OrgB`'s merge queue or continuous deployment, despite the request never being authenticated against `OrgB`'s credentials.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
