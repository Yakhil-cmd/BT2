### Title
Webhook signature verification keys the trusted secret off an unauthenticated payload field (`repository.owner.login`), decoupled from the `repository.full_name` field that handlers actually act on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
This is the closest in-engine analog to the reported bug class: a field that is *used to authorize/validate* an action is not the same field that is *acted upon*, so the verification is not actually binding the two together. In the smart-contract report, the spend counter is incremented from `callData_` before the transfer's success is checked, so "amount validated" ≠ "amount actually moved." In Shipit, the *organization used to select/verify the HMAC secret* is not cryptographically bound to the *repository the webhook actually mutates state for*.

### Finding Description
`Shipit::WebhooksController#verify_signature` selects which GitHub App/secret to validate the inbound webhook signature against using a value taken straight from the **unverified** JSON body: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
```

`repository_owner` is parsed directly from the same untrusted payload that the signature is supposed to authenticate: [2](#0-1) 

In a multi-org Shipit deployment (a documented, supported configuration — `test/dummy/config/secrets_double_github_app.yml`), `Shipit.github(organization:)` looks up a distinct app/secret per organization key: [3](#0-2) 

Once the signature is verified for *that org's secret*, `create` dispatches to handlers keyed only by the event type, with no re-check that the org used for verification matches the repository the handler will act on: [4](#0-3) 

Every handler then resolves its target purely from `payload.dig('repository', 'full_name')` — a *different* field of the same body, never covered by the org-selection logic used for signature verification: [5](#0-4) [6](#0-5) 

**The broken binding (as an equality):**
`organization whose secret authenticated the HMAC` should equal `organization that owns the repository the handler mutates`, but the code only enforces:
`HMAC(secret[payload.repository.owner.login], raw_body) == X-Hub-Signature`
while the actual state change is performed against:
`Repository.from_github_repo_name(payload.repository.full_name)`

Nothing ties `payload.repository.owner.login` to `payload.repository.full_name` — both are attacker-supplied JSON fields inside the same signed blob, and the signature only proves the raw bytes were sent by *someone who knows the secret for the org named in `repository.owner.login`*, not that this org is the true owner of `repository.full_name`.

### Impact Explanation
An attacker who is an admin/owner of **any one** GitHub organization/installation configured in a multi-org Shipit deployment (i.e., knows that org's `webhook_secret`) can forge a webhook whose `X-Hub-Signature` is computed with their own known secret, while setting `repository.owner.login` to their own org (so `verify_signature` picks their secret and it matches) but `repository.full_name` to an entirely different, victim organization's repository tracked by another Stack. Because handlers resolve the target purely via `full_name`, this is treated as trusted and dispatches, e.g.:
- `PushHandler` → enqueues `stack.sync_github(expected_head_sha: ...)` for the victim stack, forcing a resync to an attacker-chosen SHA.
- `StatusHandler` → creates a fabricated commit `Status` on a real victim commit via `commit.create_status_from_github!`, which can be used to fake CI/commit-status checks that Shipit gates deploy-readiness on.
- `CheckSuiteHandler`/`PullRequest` handlers similarly act on `full_name`-resolved stacks/PRs cross-organization.

This crosses an authorization boundary between organizations that the multi-app config is explicitly meant to isolate (each org's secret should only authorize webhooks for that org's own repositories), enabling cross-repository/cross-org state manipulation and potentially unblocking an unauthorized deploy by forging a passing CI status. This matches the "unauthorized deploy" / cross-repository-writes impact bucket.

### Likelihood Explanation
Requires: (1) the deployment uses the multi-org GitHub App config (a documented, supported Shipit configuration), and (2) the attacker controls or knows the `webhook_secret` for at least one of the configured organizations (e.g., they are an admin of their own org where the same Shipit GitHub App happens to also be installed, or they otherwise obtained one org's secret through the normal GitHub App installation UI as an org admin — not requiring any Shipit-side privileged credential). Given that condition, forging the cross-repo payload requires no further access — it's a single crafted HTTP POST to the public `/webhooks` endpoint.

### Recommendation
In `verify_signature`, after determining the organization used for signature verification, cross-check that `repository.owner.login` (or `organization.login`) actually matches the owner embedded in `repository.full_name`, and/or re-derive/validate that the resolved `Repository`/`Stack` for `full_name` belongs to the organization whose secret verified the signature, before dispatching to handlers. Alternatively, look up the target `Repository`/`Stack` first and use *its own* configured organization/secret to verify the signature, rather than trusting an unauthenticated body field to select the verification secret.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgOne` and `OrgTwo`, each with its own `webhook_secret` (per `test/dummy/config/secrets_double_github_app.yml`), where `OrgTwo` hosts the victim's tracked Stack/repository.
2. As an attacker who is an admin of `OrgOne` (and thus knows `OrgOne`'s `webhook_secret` from the GitHub App settings), craft a `push` event body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgOne" },
    "full_name": "OrgTwo/victim-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=HMAC(OrgOne_webhook_secret, raw_body)`.
4. POST to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "OrgOne")`, verifies successfully against the attacker-known secret.
6. `PushHandler#process` resolves `stacks` via `payload.dig('repository','full_name')` = `"OrgTwo/victim-repo"`, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's stack — despite the attacker never possessing `OrgTwo`'s webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
