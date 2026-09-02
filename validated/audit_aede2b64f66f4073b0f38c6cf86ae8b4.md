### Title
Cross-organization webhook forgery via mismatched signature-verification organization and payload repository target - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App (and therefore the `webhook_secret` used for HMAC verification) using `repository_owner`, a field read directly out of the untrusted JSON payload, before the payload's authenticity is established. Every webhook `Handler` (e.g. `PushHandler`) then resolves the actual `Stack`/`Repository` to act on using a *different* payload field, `repository.full_name`. Because nothing binds these two fields together, an attacker who controls a legitimately configured (but low-trust) GitHub App/organization in a multi-org Shipit deployment can sign a payload with their own org's webhook secret while setting `repository.full_name` to point at a completely different, victim organization's repository/stack.

### Finding Description
`verify_signature` picks which GitHub App config to validate against purely from attacker-controlled JSON: [1](#0-0) [2](#0-1) 

The signature is HMAC-verified with the secret belonging to whatever organization `repository_owner` names: [3](#0-2) 

Once verification passes, the raw event handlers dispatch based on a *separate* field of the same untrusted body — `repository.full_name` — to resolve which `Repository`/`Stack` the event applies to: [4](#0-3) 

`PushHandler`, for example, uses that resolved stack set to trigger a real sync against GitHub with an attacker-chosen `after` SHA: [5](#0-4) 

Shipit explicitly supports multiple independently configured GitHub Apps/organizations, each with its own `webhook_secret`, confirming this is a supported deployment topology and not an edge case: [6](#0-5) [7](#0-6) 

The binding that should hold is:
`organization authenticated by the signature check == organization owning the repository the handler acts on`

Because `repository_owner` (used to pick the verification secret) and `repository.full_name` (used to pick the target `Stack`) are two independent, unauthenticated fields in the same JSON body, this equality is never enforced. An attacker who legitimately controls one configured org (`AttackerOrg`, with a known `webhook_secret` they set up themselves) can sign a payload with their own secret while forging `repository.full_name` to reference `VictimOrg/some-repo`.

### Impact Explanation
This lets an attacker who only possesses valid webhook credentials for *any* one org configured in the Shipit instance (their own org) forge events attributed to a completely unrelated org's repositories/stacks:
- `PushHandler` triggers `stack.sync_github(expected_head_sha:)` on the victim's real stack with an attacker-chosen commit SHA, forcing sync/deploy machinery to run against a target the attacker was never authorized to touch.
- `StatusHandler`/`CheckSuiteHandler`/pull-request handlers similarly operate on the target resolved from `repository.full_name`, letting an attacker inject fabricated commit statuses, check-run refreshes, or merge/label state transitions that can influence deploy readiness and unlock deploy/merge actions on the victim stack.

This crosses an authentication boundary (the signature nominally proves "this organization sent this event") while the actual effect lands on a different organization's resources, i.e. cross-repository actions and potential triggering of unauthorized deploy/merge workflows — matching the engine's "Critical" impact bucket (cross-repository writes / unauthorized deploy, rollback or merge).

### Likelihood Explanation
Exploitation only requires the attacker to control (or be an admin of) one legitimately configured GitHub App/organization on the same Shipit instance — no access to the victim's secrets, tokens, or `ApiClient` is needed, and no session or API-client credential is required, satisfying the rules' unprivileged-attacker constraint. The mismatch is trivial to produce: it's a single JSON field (`repository.full_name`) that is never cross-checked against `repository.owner.login`/`organization.login`.

### Recommendation
After signature verification succeeds, re-derive and enforce that the organization used to select/verify the webhook secret is identical to the organization owning `repository.full_name` (and any other repository/org identifiers consumed later by handlers) before dispatching to `Shipit::Webhooks.for_event`. Reject the request (e.g. `head(422)`) if these do not match.

### Proof of Concept
1. Attacker administers `AttackerOrg`, a legitimately configured GitHub App in the same Shipit deployment (per multi-org config support), and knows its `webhook_secret`.
2. Attacker crafts and signs, with `AttackerOrg`'s own secret, a `push` webhook body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "AttackerOrg" },
    "full_name": "VictimOrg/production-repo"
  }
}
```
3. `POST /webhooks` with header `X-Github-Event: push` and `X-Hub-Signature: sha1=<hmac(AttackerOrg_secret, body)>`.
4. `verify_signature` computes `repository_owner == "AttackerOrg"`, fetches `Shipit.github(organization: "AttackerOrg")`, and the signature check passes because the attacker signed with their own valid secret.
5. `WebhooksController#create` dispatches to `PushHandler`, which reads `repository.full_name == "VictimOrg/production-repo"` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's real stack — an action the attacker had no authorization to trigger.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
