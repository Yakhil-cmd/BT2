### Title
Cross-Organization Webhook Signature Confusion — Attacker's own GitHub App secret authenticates payloads targeting a different organization's stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization deployments (`config/secrets.yml` keyed by organization name), `WebhooksController#verify_signature` selects the `GitHubApp` (and thus the webhook secret) used to validate the HMAC signature based on `repository_owner`, a value read straight out of the attacker-supplied JSON body. The `create` action's event handlers, however, resolve the actual `Stack`/`Repository` to act on using a *different* field from the same body: `repository.full_name`. Because these two fields are never required to be consistent, and both are entirely attacker-controlled in a forged POST body, an attacker who legitimately controls one onboarded GitHub organization (and therefore knows that organization's `webhook_secret`) can sign a payload with their own secret while pointing `repository.full_name` at a stack belonging to a completely different, unrelated organization also configured on the same Shipit instance.

### Finding Description
`verify_signature` resolves the signing app like this: [1](#0-0) 
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
```
`repository_owner` is taken directly from the untrusted, attacker-controlled JSON body: [2](#0-1) 

`Shipit.github(organization:)` looks up the app/secret purely by that organization name, from the multi-org config schema: [3](#0-2) 

Once signature verification passes, `create` dispatches the *entire raw payload* to the event handlers: [4](#0-3) 

But the handlers resolve the target repository/stack using a *different* field of the same body — `repository.full_name` — with no cross-check against `repository_owner`: [5](#0-4) 

For example `PushHandler` uses that repository's stacks to trigger a GitHub sync based on attacker-supplied `ref`/`after` (commit sha) values: [6](#0-5) 

**The broken binding:** the organization whose webhook secret is used to *authenticate* the request (`repository_owner`, derived from `repository.owner.login` or fallback `organization.login`) is not enforced to equal the organization that owns the repository actually *written to* (`repository.full_name`, used by `Handler#stacks`). An attacker who is a legitimate member/admin of "OrgAttacker" (with its own installed GitHub App and known `webhook_secret`) can:

1. Build a JSON body with `repository.full_name = "OrgVictim/target-repo"` (pointing to a stack managed for a different tenant org on the same Shipit instance) but `repository.owner.login = "OrgAttacker"` (or `organization.login = "OrgAttacker"`).
2. Sign the raw body with OrgAttacker's own known `webhook_secret` using `sha1=` HMAC.
3. POST to `/webhooks` with `X-Github-Event: push` (or `status`, `check_suite`, etc.).

`verify_signature` calls `Shipit.github(organization: "OrgAttacker")`, gets OrgAttacker's `GitHubApp`, and successfully verifies the signature against the attacker's own secret. `head(422)` is never invoked because `verified` is `true`. The subsequent handler dispatch then acts on `repository.full_name = "OrgVictim/target-repo"`, triggering a `GithubSyncJob`/status update/etc. for a stack the attacker has no legitimate access to.

### Impact Explanation
This crosses an organization/authentication boundary the "Escalation into `Shipit.github_teams` authorization" / "unauthorized deploy" impact bar covers: it allows a party who only controls one tenant's GitHub App configuration on a shared Shipit install to inject forged, authenticated-looking webhook events (push/status/check_suite/pull_request) against another tenant's stacks. Depending on the handler, this can force spurious `GithubSyncJob` executions with attacker-chosen `expected_head_sha`, forge commit `Status` records with attacker-chosen `state`/`target_url`/`description`, or manipulate merge/PR-related state (`OpenedHandler`, `ClosedHandler`, etc.) for a repository/stack the attacker does not own — undermining the deploy pipeline's trust model for the multi-org configuration this engine explicitly supports (`docs/setup.md`, "Using Multiple Github Applications").

### Likelihood Explanation
Requires the target Shipit instance to be configured with the multi-organization github config schema (top-level keys are org names) and requires the attacker to already control one of those configured organizations (and thus its `webhook_secret`) — a scenario explicitly documented and supported by this engine (`docs/setup.md`, `test/dummy/config/secrets_double_github_app.yml`). No other credential (no session, no `ApiClient` token) is needed; the attacker only needs the ability to compute an HMAC with a secret they legitimately possess for their own organization, and to freely craft the JSON body's `repository.full_name`/`repository.owner.login` fields.

### Recommendation
In `WebhooksController#verify_signature`, or in `Shipit::Webhooks::Handlers::Handler#stacks`, cross-check that the `repository_owner` used to select the verifying `GitHubApp` matches the owner encoded in `repository.full_name`. Concretely, derive both the app-selection key and the repository lookup key from the same trusted, single field (or validate `repository.full_name.split('/').first.casecmp?(repository_owner)` before dispatching handlers) so a payload cannot be authenticated under one organization's secret while acting on another organization's repository/stack.

### Proof of Concept
Given a Shipit instance configured with two orgs, `OrgAttacker` and `OrgVictim`, each with distinct `webhook_secret`s (as in `test/dummy/config/secrets_double_github_app.yml`):

```ruby
payload = {
  "ref" => "refs/heads/master",
  "after" => "deadbeef" * 5,
  "repository" => {
    "full_name" => "OrgVictim/target-repo", # stack the attacker does not control
    "owner" => { "login" => "OrgAttacker" }  # org the attacker legitimately controls
  }
}.to_json

signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", org_attacker_webhook_secret, payload)

post "/webhooks", body: payload, headers: {
  "X-Github-Event" => "push",
  "X-Hub-Signature" => signature
}
# verify_signature resolves Shipit.github(organization: "OrgAttacker") and passes,
# then PushHandler#stacks resolves Repository.from_github_repo_name("OrgVictim/target-repo")
# and enqueues GithubSyncJob for OrgVictim's stack.
```

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
