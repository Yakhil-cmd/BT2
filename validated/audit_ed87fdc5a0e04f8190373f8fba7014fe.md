### Title
Webhook signature is verified against an org derived from the payload while handlers act on a different, un-verified repository field — cross-repository status/stack forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
This is the same trust-binding break as the Ajna `transferLPs` bug (an action is gated by one form of authorization while the actual effect operates on a different, unchecked target). In Shipit's multi-organization mode, `WebhooksController#verify_signature` selects *which* GitHub App/webhook secret to validate the HMAC signature against using `repository_owner`, which is read straight out of the untrusted JSON payload. The event handlers that subsequently act on the payload use a *different* payload field (`repository.full_name`, or in `StatusHandler`'s case, no repository scoping at all) to decide what data to mutate. Because both fields come from the same attacker-controlled payload but the signature only proves "this body was signed by the secret belonging to `repository_owner`'s org," an attacker who owns any org configured in `secrets.github` can forge a webhook that is validly signed for their own org but whose `repository.full_name` (or `sha`) targets a different, victim-owned stack.

### Finding Description
- `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` and uses it to pick the `GitHubApp`/secret for HMAC verification: [1](#0-0) [2](#0-1) 
- Handlers, however, resolve the target repository/stack from `repository.full_name` in the same payload: [3](#0-2) , and PR handlers similarly use `params.repository.full_name`: [4](#0-3) 
- `StatusHandler` is worse: it doesn't even use `repository.full_name` — it looks up `Commit.where(sha: params.sha)` globally, with no repository/stack scoping at all: [5](#0-4) 
- In multi-org configuration, each org gets its own `webhook_secret` via `Shipit.github(organization:)`: [6](#0-5)  and `docs/setup.md` documents this multi-org layout is a supported/first-class configuration: [7](#0-6) 

**Binding broken (equality that should hold but doesn't):**
`organization used to select/validate the webhook secret (repository.owner.login)` == `organization/repository whose stack/commit data is mutated (repository.full_name / commit.sha lookup)`

Before attacker's request: victim org "victim-org" has its own webhook secret configured; attacker's own org "attacker-org" is also configured (a legitimate, independent GitHub App installation the attacker fully controls, e.g. because they administer their own org's Shipit-integrated app).
After attacker's request: attacker sends a POST to `/webhooks` with `X-Github-Event: status` (or `push`), HMAC-signs the raw body with attacker-org's *own* webhook secret, sets `repository.owner.login` = `"attacker-org"` (so `verify_signature` picks attacker-org's secret and the signature checks out), but sets `sha` (for `status`) or `repository.full_name` (for `push`/PR events) to reference a commit/stack that belongs to `victim-org`. `verify_signature` passes because it only checked "was this signed by attacker-org's secret," never "does attacker-org actually own the repository these params claim to mutate."

### Impact Explanation
- Via `StatusHandler`, an attacker can inject arbitrary commit statuses (state, context, description, target_url) for **any commit in the whole Shipit install**, regardless of which stack/repo it belongs to, since the lookup is unscoped by repository. `required_statuses`/`blocking_statuses` gate whether a commit is deployable via `Stack`/`Commit` delegation: [8](#0-7) . Forging a passing status on a victim's commit that a required CI check would otherwise block can clear the way for that commit to become deployable — an unauthorized-deploy enabler.
- Via `PushHandler`/PR handlers, an attacker can trigger `stack.sync_github` or archive/unarchive review stacks belonging to a repository they don't control, using `repository.full_name` values that don't match the org whose secret signed the request: [9](#0-8) [10](#0-9) 

This matches the required Critical/High impact classes: enabling an unauthorized deploy for a repository the attacker does not control, and cross-repository state mutation, both achieved without any GITHUB_TOKEN, session, or ApiClient credential — only control of one legitimately-configured (but unrelated) org in a multi-org Shipit deployment.

### Likelihood Explanation
Requires a multi-organization Shipit deployment (`secrets.github` keyed by org, as documented) and requires the attacker to control (or have compromised) at least one of the configured orgs enough to know/derive its `webhook_secret` (e.g., they are the admin of their own org's GitHub App installed into the same Shipit instance) — a realistic scenario for shared/hosted Shipit instances serving multiple orgs/teams. No other privilege (no Shipit login, no API token) is needed, matching the "unprivileged attacker" framing of the analog rule set. This is a plausible but not certain deployment pattern, so likelihood is Medium-High rather than certain.

### Recommendation
Verify the signature using the secret for the organization *actually referenced by the fields the handlers will act on* (i.e., derive `repository_owner` consistently and re-validate that `repository.full_name`'s owner matches the org whose secret validated the signature), and make every handler (especially `StatusHandler`) scope its lookups by the verified repository/stack rather than trusting an independent, unverified field from the same payload.

### Proof of Concept
1. Configure Shipit in multi-org mode with `victim-org` and `attacker-org` (the latter fully controlled by the attacker, e.g. the attacker installed their own GitHub App as documented in `docs/setup.md`).
2. Attacker crafts a `status` event payload: `{"sha": "<victim commit sha>", "state": "success", "context": "ci/required-check", "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/whatever"}}`.
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s own `webhook_secret` (which they know, since it's their own app) over the raw JSON body.
4. `WebhooksController#verify_signature` extracts `repository_owner = "attacker-org"`, loads `Shipit.github(organization: "attacker-org")`, and the signature verifies successfully [1](#0-0) .
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim's commit anywhere in the install — and calls `create_status_from_github!`, injecting a forged "success" status on a commit in `victim-org`'s stack [5](#0-4) , potentially satisfying `required_statuses` and enabling an unauthorized deploy of that commit.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** lib/shipit.rb (L170-181)
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

**File:** app/models/shipit/commit.rb (L57-58)
```ruby
    delegate :broadcast_update, :github_repo_name, :hidden_statuses, :required_statuses, :blocking_statuses,
             :soft_failing_statuses, to: :stack
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
