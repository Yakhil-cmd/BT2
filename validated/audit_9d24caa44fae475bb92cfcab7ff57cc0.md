### Title
Cross-organization webhook forgery via mismatched signature-selection and payload-processing fields - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App / webhook secret to verify a request against using `repository.owner.login` (or `organization.login`) from the *untrusted* JSON body, while the event handlers that actually act on the payload (`Shipit::Webhooks::Handlers::Handler#repository_name`) resolve the target `Stack`/`Repository` using a *different* field of the same untrusted body: `repository.full_name`. Nothing enforces that these two fields refer to the same organization.

### Finding Description
In a multi-organization Shipit deployment (`config/secrets.yml` keyed per-organization, as documented for "multiple Github applications for different Github organizations"), each organization has its own `webhook_secret`.

`verify_signature` picks the app/secret to verify against like this: [1](#0-0) [2](#0-1) 

That is, `repository_owner` (`repository.owner.login` / `organization.login`) drives `Shipit.github(organization: repository_owner)`, which loads the org-specific `webhook_secret` via `github_app_config`: [3](#0-2) 

Once the HMAC check passes, `create` dispatches the *entire raw payload* to handlers: [4](#0-3) 

But the handlers determine which repository/stack to act on using a **different** field — `repository.full_name` — not `repository.owner.login`: [5](#0-4) 

Since `repository.owner.login` (used for org/secret selection) and `repository.full_name` (used for target-repository resolution) are two independent, attacker-controlled JSON fields in the same webhook body, an attacker who legitimately controls the webhook secret for **their own** organization ("orgA") can forge a payload whose `repository.owner.login`/`organization.login` is `"orgA"` (so the HMAC signed with orgA's secret validates) while `repository.full_name` is set to `"orgB/some-repo"` — a stack belonging to a completely different organization the attacker has no access to. `verify_signature` will accept it, and `PushHandler`/`StatusHandler`/etc. will then operate on `orgB`'s `Stack` because `Handler#repository_name` only reads `full_name`.

This is exactly the "organization that authenticated versus the repository that is written" binding break: the equality that should hold is `repository.owner.login (verified) == full_name.split('/').first (acted upon)`, and it is never enforced.

### Impact Explanation
Concretely reachable handlers act on the mismatched repository:
- `PushHandler` triggers `stack.sync_github(expected_head_sha: ...)` on the attacker-chosen `orgB` stack [6](#0-5) , forcing synchronization off attacker-influenced data.
- `StatusHandler` (registered for the `status` event) [7](#0-6)  can be used to inject fabricated commit statuses for commits in `orgB`'s repository, which Shipit's CI-gating (`ci.require`) uses to decide whether a deploy can proceed — enabling an attacker who only controls their own organization's webhook secret to influence deploy readiness for an unrelated organization's stack. This crosses the "cross-repository writes / unauthorized deploy" impact bar.

### Likelihood Explanation
Any entity that legitimately operates a GitHub App/organization onboarded to a shared, multi-tenant Shipit instance (a normal, documented configuration — see `config/secrets.development.example.yml`'s multi-org schema) already knows its own `webhook_secret` and can freely craft POST bodies to `/webhooks` with any `repository.full_name`. No privileged Shipit account, session, or `ApiClient` token is required — only a valid signature for the attacker's *own* organization, which the attacker inherently possesses.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler`), enforce that the organization used to select the webhook secret matches the owner segment of `repository.full_name` (and `organization.login` when present) before dispatching to handlers, rejecting the payload otherwise.

### Proof of Concept
1. Attacker administers GitHub App/org `orgA` on a multi-org Shipit instance and knows `secrets.github[:orgA][:webhook_secret]`.
2. Attacker crafts a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature` using `orgA`'s webhook secret and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "orgA")`, validates successfully against `orgA`'s secret.
5. `PushHandler#process` resolves `Repository.from_github_repo_name("orgB/victim-repo")` and calls `sync_github` on `orgB`'s stack — despite the request only ever being authenticated as `orgA`.

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

**File:** app/models/shipit/webhooks.rb (L19-19)
```ruby
          'status' => [Handlers::StatusHandler],
```
