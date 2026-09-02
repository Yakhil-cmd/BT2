### Title
Cross-tenant CI status/state forgery via organization-scoped webhook signature verification decoupled from the repository actually written - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate a webhook against based on an attacker-controlled field in the JSON body (`repository.owner.login` / `organization.login`), while the handlers that actually mutate state (in particular `StatusHandler`) act on data (`sha`) with **no repository/organization scoping at all**. In a multi-organization Shipit deployment (`Shipit.github_organizations`/`github_app_config`), a party who legitimately controls a webhook secret for **one** organization/repo hooked into the instance can forge a `status` (or other) webhook payload that is authenticated against their own org's secret but whose effects are applied globally, including to commits/stacks belonging to a completely different organization they do not control.

### Finding Description
`WebhooksController#verify_signature` derives the authenticating organization solely from the untrusted payload: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up a distinct `GitHubApp` instance/secret per organization via `github_app_config`: [3](#0-2) 

So in a multi-org configuration, each organization has its own `webhook_secret`, and the HMAC is verified only against the secret belonging to whichever organization the attacker names in `repository.owner.login`/`organization.login`.

Once the signature passes, `params` (the raw JSON body) is dispatched to handlers via `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`: [4](#0-3) 

Most handlers re-scope by `repository.full_name` (a separate, independently-controlled field of the same JSON body) via `Handler#stacks`: [5](#0-4) 

But `StatusHandler` — used for GitHub `status` webhooks, which drive Shipit's CI-status/deployability model — does **no repository scoping whatsoever**: it looks up commits globally by SHA across the entire installation: [6](#0-5) 

The binding that should hold is: `organization authenticated by verify_signature == organization/repository whose state the handler is permitted to write`. Because the field used for authentication (`repository.owner.login`/`organization.login`) is never bound to the field(s) used for the actual write (`sha` in `StatusHandler`, unrelated to any repository), an attacker who holds a valid webhook secret for **any one** organization configured on the Shipit instance can craft a payload where:
- `repository.owner.login` = the attacker's own organization (so `verify_signature` picks the attacker's own `webhook_secret` and succeeds), and
- `sha` = a commit SHA belonging to a **different** organization's stack (or state = "success"/"failure" for any commit anywhere in the install).

`StatusHandler#process` then finds `Commit.where(sha: params.sha)` irrespective of which repository the signature was verified for, and calls `commit.create_status_from_github!(params)`, injecting an arbitrary CI status onto that unrelated stack's commit.

### Impact Explanation
Shipit's `Stack` deployability and Continuous Delivery gating rely on commit CI status (`required_statuses`, `Status::Group`, `ContinuousDeliveryJob`). By forging a passing status for a target organization's commit — despite having credentials for a completely unrelated, attacker-controlled organization — an attacker can make an otherwise CI-blocked commit on someone else's stack appear "green," which can unblock manual deploys or trigger automatic continuous delivery, resulting in an **unauthorized deploy** on a stack/repository the attacker does not control. This satisfies the High-impact bar ("escalation into authorization ... unauthenticated read of stack state ... or an unauthorized deploy"), and depending on stack configuration could rise to Critical (unauthorized deploy).

### Likelihood Explanation
This requires the attacker to hold a legitimate webhook secret for at least one organization/repository configured in the same multi-tenant Shipit instance (e.g., they administer their own org's GitHub App/webhook pointed at this Shipit deployment) — a realistic scenario for any Shipit installation serving multiple GitHub organizations, since organization webhook secrets are configured independently and are not meant to authorize actions on other organizations' data. No GitHub-side repository write access or Shipit session is needed. Likelihood is Medium: it's gated by multi-org hosting and possession of one valid webhook secret, but no privileged Shipit credential is needed at all.

### Recommendation
Bind the authenticated organization/repository to the data being mutated:
- In `WebhooksController`, after `verify_signature`, pass the verified `repository_owner`/organization down to each handler and require handlers to filter by it (not just by `repository.full_name` taken from the same untrusted body, but cross-checked against the authenticated org).
- Fix `StatusHandler#process` specifically to scope `Commit` lookups through the stack's `repository` (and that repository's owner) matching the organization that authenticated the request, e.g. `stacks.joins(:commits).where(commits: { sha: params.sha })` instead of a global `Commit.where(sha: params.sha)`.
- More generally, verify that `repository.owner.login`/`organization.login` used for signature selection is consistent with `repository.full_name` used for entity resolution before processing.

### Proof of Concept
1. Operate (or control the webhook secret of) `attacker-org/some-repo`, configured in this Shipit instance's `secrets.github[:attacker-org]`.
2. Identify a commit SHA belonging to `victim-org/victim-repo`'s stack that is pending CI (e.g., from public GitHub data).
3. POST to `/github/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/some-repo" }
}
```
4. Sign the raw body with `attacker-org`'s known `webhook_secret` and set `X-Hub-Signature` accordingly.
5. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and successfully verifies the HMAC.
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and finds the victim commit regardless of repository, creating a forged passing status on `victim-org/victim-repo`'s commit — potentially unblocking or triggering a deploy on a stack the attacker has no authorization over.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
