## Title
Cross-organization webhook forgery via attacker-controlled `repository.owner.login` used to select the signature-verification secret while a different, unrelated repository field drives the actual write - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In a multi-organization Shipit deployment, `WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate the inbound signature against using a value taken **from the unauthenticated request body itself**, before the signature has been verified. The value ultimately used by the event handlers to decide *which stack/repository actually gets written to* is a different field of the same untrusted payload. Because both values are attacker-controlled prior to any cryptographic check, an attacker who knows (or who legitimately possesses) the webhook secret for *any* configured organization can forge a payload that is verified against that known-organization's secret while directing the actual write (triggering a `GithubSyncJob`, updating commit statuses, opening/closing "review stacks", etc.) at a stack belonging to a *different* organization/repository.

### Finding Description
`verify_signature` picks the GitHub App config purely from payload data: [1](#0-0) [2](#0-1) 

`repository_owner` reads `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`) straight out of `JSON.parse(request.raw_post)` — i.e., attacker-supplied JSON, unverified at this point. `Shipit.github(organization: repository_owner)` then resolves the `GitHubApp` (and its `webhook_secret`) for whatever organization name the attacker put in that field: [3](#0-2) 

Signature verification itself is: [4](#0-3) 

Note also `return true unless webhook_secret` — if an org is configured with no webhook secret (a documented/supported configuration, see `test/dummy/config/secrets_double_github_app.yml` and `config/secrets.development.shopify.yml` where `webhook_secret:` is left blank), verification is unconditionally bypassed for that organization.

Meanwhile, the actual side effect of the webhook — which `Stack`/`Repository` gets acted upon — is derived from a *different* payload field, `repository.full_name`, read again from the same untrusted JSON body by the handler base class and every concrete handler: [5](#0-4) [6](#0-5) [7](#0-6) 

Nothing enforces that the organization embedded in `repository.full_name` (used to look up the `Repository`/`Stack` to mutate) matches the organization used to select the verification secret (`repository.owner.login`/`organization.login`). Both are just sibling keys inside the same attacker-forged JSON body, since the signature has not yet been established as valid when `repository_owner` is read.

This is the direct analog of the reported bug class: a field the trust decision is based on (`repository_owner`, used to pick the verifying secret) is not the field bound to the actual privileged action (`repository.full_name`, used to select the repository/stack that is written to) — i.e., "an organization that authenticated versus the repository that is written" binding is broken.

**Binding that should hold:** `organization_used_to_verify_signature == organization_of_repository_actually_written`.
**What actually happens:** `organization_used_to_verify_signature = payload['repository']['owner']['login']` (or `payload['organization']['login']`), while `organization_of_repository_actually_written = owner_prefix_of(payload['repository']['full_name'])`. Both come from the same unauthenticated body and can be set independently by the attacker before any signature is checked.

### Impact Explanation
An attacker who knows a valid webhook secret for organization A (e.g., because they administer a legitimate Shipit-integrated repo under org A, or because org A's app was configured with no webhook secret at all, which is a documented supported state) can forge a webhook whose `repository.owner.login`/`organization.login` = `"OrgA"` (so it verifies with OrgA's secret or the no-secret bypass) but whose `repository.full_name` = `"OrgB/victim-repo"`. This drives handlers that operate on OrgB's stacks:
- `PushHandler` calls `stack.sync_github(expected_head_sha: params.after)` for any non-archived stack on the victim branch — forcing a `GithubSyncJob` sync against an attacker-chosen `after` SHA.
- `PullRequest::OpenedHandler`/`ClosedHandler`/etc. can create/close review stacks for the victim repository.
- `StatusHandler`/`CheckSuiteHandler` can inject fabricated commit statuses/check-run refreshes for the victim repository's commits, which downstream deploy-gating logic in Shipit treats as authoritative CI signal.

This crosses a repository/organization boundary using credentials that were never meant to authorize actions on that repository — this is the "cross-repository writes" impact category (unauthorized manipulation of a different organization's stack state, and potential unauthorized deploy triggers via forged commit statuses that satisfy deploy-gating checks).

### Likelihood Explanation
Requires the attacker to know or control one organization's `webhook_secret` (or exploit an org configured without one — a state the codebase explicitly supports, per `secrets_double_github_app.yml` / `secrets.development.shopify.yml` templates) in a multi-org Shipit instance, and to know/guess the victim organization's repository full name (public information for public repos). No GitHub App private key, session, or `ApiClient` token is required — only the ability to POST to the public `/webhooks` endpoint. This is a realistic configuration for any Shipit deployment serving multiple GitHub organizations.

### Recommendation
Verify the signature independently of any organization value taken from the parsed payload, or, if a per-organization secret must be selected, validate after the fact that the organization used for the successful signature match is the *same* organization that owns `repository.full_name` before invoking handlers. Concretely:
- Require signature verification to try all configured organizations' secrets and only proceed if the winning organization's expected repository owner matches the payload's `repository.full_name` owner (case-insensitively).
- Reject the webhook if `repository.owner.login` (or `organization.login`) does not match the owner segment of `repository.full_name`.

### Proof of Concept
Given two configured organizations, `OrgA` (webhook secret known to attacker or blank) and `OrgB` (victim, hosting stack `OrgB/victim-repo`):

```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=<computed with OrgA's secret over the raw body below>

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "full_name": "OrgB/victim-repo",
    "owner": { "login": "OrgA" }
  }
}
```

`WebhooksController#verify_signature` computes `repository_owner => "OrgA"`, fetches OrgA's `GitHubApp`, and successfully verifies the signature (known/blank secret). `PushHandler#stacks` then resolves `Repository.from_github_repo_name("OrgB/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on OrgB's stack, even though the signature was never checked against OrgB's secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
