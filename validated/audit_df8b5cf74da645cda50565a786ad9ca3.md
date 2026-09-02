### Title
Webhook Signature is Verified Against an Attacker-Controlled Organization While Event Handlers Act on an Unrelated Repository Field - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/organization whose secret is used to validate the HMAC based on `repository.owner.login` (fallback `organization.login`) taken from the untrusted JSON body itself, while the event handlers that actually mutate state (e.g. `PushHandler`, `CheckSuiteHandler`) select the target `Repository`/`Stack` using a completely different, unchecked field: `repository.full_name`. Nothing in the request path enforces that the organization whose secret signed the payload matches the repository that the handler subsequently writes to.

### Finding Description
`verify_signature` picks the signing secret this way: [1](#0-0) [2](#0-1) 

i.e. `repository_owner` (used only to pick the HMAC secret) comes straight from the JSON body's `repository.owner.login`/`organization.login`.

`verify_webhook_signature` then just checks the raw body against that org's `webhook_secret`: [3](#0-2) 

Once the signature check passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs handlers on the whole, still fully attacker-controlled JSON body: [4](#0-3) 

Handlers resolve the target repository/stack from an entirely different field, `repository.full_name`, with no cross-check against `repository.owner.login`/`organization.login` used for signature selection: [5](#0-4) 

`PushHandler` uses that repository/stack lookup to force a stack sync at an attacker-chosen commit: [6](#0-5) 

`CheckSuiteHandler` similarly acts on any repository whose `full_name` is supplied, independent of which org's secret validated the request: [7](#0-6) 

**Broken binding (as an equality):**
`organization_that_signed(repository.owner.login used by verify_signature)` is assumed to equal `repository_that_is_written(repository.full_name used by Handler#stacks)`, but this equality is never checked. In Shipit's multi-tenant model, `Shipit.github(organization: X)` resolves per-organization webhook secrets, so an attacker who administers a GitHub App/webhook integration for *their own* onboarded organization ("attacker-org") knows that organization's `webhook_secret` (they configured it when installing the App). They can therefore produce a validly-signed webhook whose `repository.owner.login`/`organization.login` is `attacker-org` (so `verify_signature` succeeds), but whose `repository.full_name` names an unrelated, victim-owned stack (e.g. `"victim-org/victim-repo"`), and whose `ref`/`after` fields are fully attacker-chosen.

### Impact Explanation
This crosses a repository-write boundary: an actor with only their own organization's webhook credentials can cause `PushHandler` to invoke `stack.sync_github(expected_head_sha: params.after)` on a victim's `Stack` that they have no authorization over, using an attacker-chosen `after` SHA. Depending on the victim stack's continuous-deployment configuration, forcing a sync at an attacker-chosen head can lead to an unscheduled/unauthorized deploy trigger on a repository the attacker does not control — matching the engine's "cross-repository writes / unauthorized deploy" Critical impact category. `CheckSuiteHandler` similarly allows forcing check-run refreshes on an arbitrary victim stack.

### Likelihood Explanation
This is only exploitable in a multi-tenant Shipit deployment where more than one organization/GitHub App is configured (so more than one `webhook_secret` exists and an attacker legitimately administers one of them), and it requires the attacker to already control a GitHub App/webhook integration onboarded to that Shipit instance (i.e., they are already a trusted, if scoped, tenant). It does not require Shipit session credentials, `ApiClient` tokens, or repository write access to the *victim* repository — only to their own onboarded org, which is the trust boundary the request explicitly claims to enforce ("verify_signature" is supposed to prove the request came from the claimed org for the claimed repository, but only proves the former).

### Recommendation
After signature verification, re-derive the repository owner from `repository.full_name` (or `organization.login`) and assert it matches the `repository_owner` used to select the webhook secret before dispatching to handlers; reject the request (422) on mismatch.

### Proof of Concept
1. Attacker administers `attacker-org`'s GitHub App integration on the target Shipit instance and knows `attacker-org`'s `webhook_secret`.
2. Attacker crafts a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(attacker-org secret, raw_body)` and POSTs to `/github/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature against the attacker's own known secret.
5. `PushHandler` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's stack — an action the attacker was never authorized to trigger.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
