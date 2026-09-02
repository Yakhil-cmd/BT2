### Title
Cross-organization webhook signature confusion allows commit status forgery leading to unauthorized deploys - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects *which* organization's webhook secret to validate a signature against based on `repository.owner.login` (or `organization.login`) taken from the unauthenticated request body, but the handler that actually processes the event (`StatusHandler`) never re-checks that field when deciding what to write. This breaks the binding: "organization that authenticated" **should equal** "repository (and its commits/stacks) that is written." An attacker who only controls a repository in *any* organization onboarded into this multi-tenant Shipit instance can forge a signature using their own org's known webhook secret while writing a forged CI status onto a commit belonging to a completely unrelated, victim repository.

### Finding Description
`WebhooksController#verify_signature` derives the signing organization purely from attacker-supplied JSON, before the signature itself has been checked: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization config (including a distinct `webhook_secret`) from `secrets.github`: [3](#0-2) 

Once the HMAC verifies against *that* organization's secret, the entire raw payload — unfiltered and un-rescoped — is dispatched to every registered handler for the event: [4](#0-3) 

`StatusHandler`, unlike other handlers (`PushHandler`, pull-request handlers) that resolve a `Repository`/`Stack` via `payload.dig('repository', 'full_name')` before acting, performs **no repository/organization scoping at all**. It looks up commits globally by `sha` across the entire Shipit database and writes a status onto every match: [5](#0-4) 

So the equality that should hold — "the organization whose secret validated the signature" == "the repository/commit being mutated" — is never enforced. The signature only proves the request was authorized by *some* onboarded organization; the handler then mutates state belonging to *any* organization's commits, because `sha` values are not namespaced per repository/org in the lookup.

### Impact Explanation
Shipit uses commit statuses to gate deploys via required/blocking CI statuses (`ci.require`, `status.context`, etc., configured in `shipit.yml`): [6](#0-5) 

By forging a `status` webhook event — signed with the attacker's own (legitimately known) organization's webhook secret — that sets `state: "success"` and the required `context` for a **victim's** commit `sha`, an attacker with zero access to the victim's repository or Shipit stack can satisfy the CI-status gate that the victim's stack relies on to authorize a deploy. This can result in an unauthorized deploy of a commit that never actually passed CI, which is explicitly listed as a Critical/High-impact outcome. No `ApiClient` token, no user session, and no GitHub write access to the victim's repository are required — only administrative control of a separate, unrelated organization's own webhook secret onboarded into the same multi-tenant Shipit deployment.

### Likelihood Explanation
This requires: (1) a Shipit deployment configured for multiple GitHub organizations with per-organization webhook secrets (a documented, supported multi-tenant configuration via `secrets.github`), and (2) the attacker to be an administrator/owner of at least one such onboarded (but otherwise unrelated/low-trust) organization, which lets them know that organization's webhook secret because they configure the webhook delivery on the GitHub side themselves. Given this configuration is explicitly supported (`github_app_config`, `TOP_LEVEL_GH_KEYS`), and commit `sha` collisions/targeting are trivial (attacker can target any known victim commit sha, e.g., visible publicly on GitHub), likelihood is realistic in any multi-org Shipit deployment.

### Recommendation
1. In `StatusHandler` (and any other handler that does not already scope by repository), restrict the `Commit` lookup to commits belonging to the same organization/repository asserted in the payload's `repository.full_name`, cross-checked against the organization whose secret validated the signature.
2. In `WebhooksController#verify_signature`, after successfully verifying the signature for `repository_owner`, propagate that verified organization identity to handlers and have every handler assert that any repository/organization referenced in the payload matches the verified one, rejecting the event otherwise.
3. Consider signing/verifying webhooks with an app-level key while additionally validating that `repository.owner.login` is consistent with the installation/organization context resolved from GitHub metadata rather than trusting the raw JSON field for secret selection.

### Proof of Concept
1. Shipit is configured with two organizations, `attacker-org` (attacker is an admin, knows its `webhook_secret`) and `victim-org` (unrelated, attacker has no access).
2. Attacker crafts a JSON body for a `status` event:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/whatever" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(attacker_org_webhook_secret, body)`.
4. POST to `/webhooks` with `X-Github-Event: status`.
5. `verify_signature` resolves `repository_owner = "attacker-org"`, verifies successfully against the known secret [1](#0-0) .
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim's commit regardless of organization — and writes the forged "success" status onto it [5](#0-4) , potentially satisfying `victim-org`'s required CI status gate for deploys.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** README.md (L444-450)
```markdown
<h3 id="ci">CI</h3>

**<code>ci.require</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want Shipit to disallow deploys if any of them is missing on the commit being deployed.

For example:
```yml
ci:
```
