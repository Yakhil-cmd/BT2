## Root cause

`WebhooksController#verify_signature` selects the GitHub App/webhook secret used to authenticate an inbound webhook based on `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`) — a field taken from the still‑unverified, attacker‑controlled JSON body: [1](#0-0) [2](#0-1) 

The signature is verified with `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`, which looks up per-organization webhook secrets keyed by that same organization string: [3](#0-2) 

Once verification passes, `WebhooksController#create` dispatches the *entire* JSON body to handlers, e.g. `PushHandler`, without re-checking that `repository.owner.login` matches `repository.full_name`: [4](#0-3) 

The handler base class then resolves the target `Stack`/`Repository` purely from `repository.full_name` — a *different* field of the same body: [5](#0-4) [6](#0-5) [7](#0-6) 

This is the exact bug class analog called out in the rules: **"an organization that authenticated versus the repository that is written."** The equality that must hold is:

`organization used to select the HMAC secret (repository.owner.login) == owner of the repository the handler actually writes to (repository.full_name)`

Nothing in the code enforces this equality; the two fields are independently attacker-controlled inside the same signed JSON body, so a valid HMAC only proves "this body was signed by the secret configured for org X," not "this body's repository/effects belong to org X."

## Why it is exploitable in a multi-tenant Shipit deployment

Multi-org configuration is real and documented: `Shipit.github_app_config` indexes distinct webhook secrets per organization key under `secrets.github`: [8](#0-7) 

In such a deployment, an attacker who legitimately owns/administers *any one* onboarded GitHub organization/repo (call it `org-attacker`) already possesses (or can trivially obtain, since GitHub delivers it to their own configured webhook endpoint / or they configured it themselves when installing the app) the webhook secret for `org-attacker`. Because `verify_signature` only proves the payload was signed with `org-attacker`'s secret, the attacker can:

1. Craft a raw JSON body where `repository.owner.login` (and/or `organization.login`) = `org-attacker` (so the correct/known secret is selected and validated), but `repository.full_name` = `victim-org/victim-repo`.
2. Sign that raw body with `org-attacker`'s real webhook secret and POST it to `/webhooks`.
3. `verify_signature` succeeds (correct secret for the claimed org), and `PushHandler` (or other handlers keying off `repository.full_name`) resolves `victim-org/victim-repo`'s `Stack` and calls `stack.sync_github(expected_head_sha: ...)`, which enqueues `GithubSyncJob` to sync commits and can drive continuous delivery / deploy scheduling for a repository the attacker does not control.

This crosses a real trust boundary (an unprivileged party who only administers their own onboarded org can act on another tenant's repository state) — matching the "unauthorized deploy" / cross-repository-writes impact class.

## Title
Webhook signature is verified against `repository.owner.login`, but handlers act on the unrelated `repository.full_name` field — allowing cross-repository webhook forgery — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the per-organization webhook secret to validate a request using `repository.owner.login`/`organization.login` from the request body, but the actual handlers (`Handler#stacks`, `PushHandler`, etc.) act on `repository.full_name`, a separate, independently attacker-controlled field of the same JSON body. No code ties these two fields together, so a valid signature for organization A does not guarantee the payload's effects are scoped to organization A's repositories.

### Finding Description
- `repository_owner` (used to choose the HMAC secret) comes straight from the unverified body: [2](#0-1) 
- `verify_webhook_signature` only proves the raw body's HMAC matches the secret configured for that claimed organization: [9](#0-8) 
- After verification, the full body is dispatched unchanged to handlers: [4](#0-3) 
- Handlers resolve the target repository/stack from a *different* field (`repository.full_name`), never cross-checked against `repository.owner.login`: [5](#0-4) 

Because GitHub App webhook secrets are configured per organization (`Shipit.github_app_config`), a tenant that legitimately controls its own org's webhook secret can forge a payload naming a victim org's repository in `full_name` while keeping `owner.login` set to their own org so the signature check passes.

### Impact Explanation
This allows cross-tenant/cross-repository writes: an attacker with a legitimate (but limited) organization's webhook secret can trigger `GithubSyncJob` (and any other handler keyed on `repository.full_name`, e.g. `commit_status`, `check_suite`, `pull_request`/review-stack handlers) against a completely different organization's stacks, causing unauthorized synchronization/deploy-scheduling activity outside their authorization scope. This matches the "cross-repository writes / unauthorized deploy" Critical impact class.

### Likelihood Explanation
Requires the target Shipit instance to be configured in multi-org mode (`secrets.github` keyed by multiple organizations) and the attacker to control one onboarded organization's webhook secret — a realistic scenario for a shared/multi-tenant Shipit deployment, and needs no privileged Shipit account, API token, or GitHub App private key.

### Recommendation
After successfully verifying the signature, reject the request (422) unless `repository.owner.login` (or `organization.login`) used for secret selection matches the owner segment of `repository.full_name` in the same payload. Alternatively, always verify the signature using the secret bound to the actual target repository (`repository.full_name`) rather than a possibly different `owner`/`organization` field.

### Proof of Concept
1. Configure Shipit with two orgs in `secrets.github`, e.g. `org-attacker` and `victim-org`, each with distinct `webhook_secret`.
2. Attacker crafts a push payload body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": { "owner": {"login": "org-attacker"}, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(org-attacker's webhook_secret, raw_body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `Shipit.github(organization: "org-attacker")` and validates the HMAC successfully.
5. `PushHandler#process` calls `stacks` → `Repository.from_github_repo_name("victim-org/victim-repo")`, matching the victim's real `Stack`, and enqueues `GithubSyncJob` for it — even though the attacker never proved control of `victim-org`.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
