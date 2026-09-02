### Title
Cross-organization webhook forgery via unverified `repository.full_name` binding - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate an inbound GitHub webhook based on the organization named in the payload's `repository.owner.login` (falling back to `organization.login`), but every event handler resolves the *target* repository/stack from the completely separate `repository.full_name` field, which is never checked against the organization that authenticated the request.

### Finding Description
`Shipit.github(organization: repository_owner)` looks up the per-organization webhook secret using `repository_owner`, defined as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) [2](#0-1) . In the multi-tenant GitHub App configuration, `Shipit.github` looks up a distinct config (and `webhook_secret`) per organization key: [3](#0-2) .

Once the signature is verified against that organization's secret, `WebhooksController#create` dispatches the raw, attacker-controlled JSON body to handlers without re-validating any field: [4](#0-3) . Every handler resolves the affected stacks purely from `payload.dig('repository', 'full_name')`, a sibling field of `repository.owner.login` that is not cross-checked: [5](#0-4) . This same unguarded lookup is reused by `PushHandler` (`stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(...) }` [6](#0-5) ) and by `StatusHandler`, which writes a commit status purely from `sha` (also global, not scoped to the verified org) [7](#0-6) .

The verified binding is: `organization that authenticated the webhook == organization named in repository.owner.login`. The binding actually acted upon by every handler is: `repository/stack mutated == repository.full_name`. Nothing enforces that `repository.full_name.split('/').first == repository_owner`, so the two can diverge. Any principal who legitimately controls a webhook for **one** onboarded organization (Org A) — i.e., who knows Org A's `webhook_secret`, a routine permission an org admin holds for their own org and not a Shipit application secret — can sign a payload where `repository.owner.login = "org-a"` (satisfying `verify_signature`) while `repository.full_name = "org-b/some-repo"` (the value actually consumed by the handlers). This forges push/status/check_suite events against a completely different tenant's stacks.

### Impact Explanation
This breaks tenant isolation between the organizations onboarded to the same Shipit instance: an operator authorized only for Org A's GitHub webhook can inject forged `push`, `status`, or `check_suite` events that are attributed to Org B's repositories/stacks. Concretely this allows: triggering `GithubSyncJob`/`stack.sync_github` for a foreign stack, and forging commit `status` records (`create_status_from_github!`) that a foreign stack's deploy-spec CI gating relies on to decide `deployable?`. Combined with the existing deploy path, an attacker can fabricate a "green" CI status on someone else's commit and thereby help trigger/allow an unauthorized deploy — a cross-repository write and unauthorized-deploy scenario, matching the Critical impact bucket in the report's rules (cross-repository writes / unauthorized deploy).

### Likelihood Explanation
Exploitation requires the attacker to already control one organization's own webhook secret (their own tenant configuration) — a routine, low-privilege capability relative to a *different* victim organization also using the same shared Shipit instance, and it requires zero access to Shipit's application secrets, `GITHUB_TOKEN`, or any Shipit session/API token. Multi-tenant deployments (multiple `github.<org>.webhook_secret` entries under one Shipit host, as documented in the config schema) are an explicit supported configuration [8](#0-7) , so this is a realistic and directly reachable configuration, not a hypothetical one.

### Recommendation
After computing `repository_owner` and verifying the signature, additionally verify that the organization prefix of `payload.dig('repository', 'full_name')` matches `repository_owner` (or `organization.login`) before dispatching to handlers, rejecting mismatched payloads with `422`. This closes the gap between the authenticated organization and the repository actually mutated by handlers.

### Proof of Concept
1. Shipit is configured with two tenants: `org-a` (secret `S_A`) and `org-b` (secret `S_B`), each with `github.<org>.webhook_secret` set, per the documented multi-org schema [9](#0-8) .
2. Attacker holds `S_A` (e.g., as the legitimate maintainer of Org A's GitHub App/webhook configuration).
3. Attacker crafts a JSON body for the `status` event:
```json
{
  "sha": "<victim-commit-sha-in-org-b-repo>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(S_A, body)` and POSTs to `/webhooks`.
5. `verify_signature` resolves `repository_owner` = `"org-a"`, fetches Org A's `GitHubApp`, and the signature validates successfully [1](#0-0) .
6. `StatusHandler#process` matches `Commit.where(sha: params.sha)` — which is not scoped to any organization — and calls `create_status_from_github!`, writing a forged CI status onto Org B's commit [7](#0-6) , even though the request was authenticated solely with Org A's secret.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
