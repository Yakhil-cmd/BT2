### Title
Signing-organization not bound to acted-upon repository in webhook processing - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to validate a webhook against using `repository_owner`, a value taken from the **unverified** JSON body (`repository.owner.login` or `organization.login`). Once the HMAC check passes, the entire raw payload — including a separate field, `repository.full_name` — is handed to event handlers (e.g. `PushHandler`) unchanged. `PushHandler` resolves the `Stack`/`Repository` to act on using `repository.full_name`, not the same field that was used to pick the verification secret. Nothing enforces that these two fields refer to the same GitHub organization/repository.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` does: [1](#0-0) [1](#0-0) [2](#0-1) 

It picks the GitHub App config (and therefore the `webhook_secret` used for HMAC verification) with `Shipit.github(organization: repository_owner)`, where `repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — both fully attacker-controlled fields inside the JSON body being verified.

`GithubApp#verify_webhook_signature` only proves that the raw body was HMAC-signed with *some* configured organization's secret — the one selected by that same attacker-controlled field: [3](#0-2) 

After verification, the raw parsed body is dispatched unmodified to handlers: [4](#0-3) 

`PushHandler` (and the base `Handler`) then determine which `Stack` to mutate using a *different* field of the same payload, `repository.full_name`: [5](#0-4) [6](#0-5) 

In a multi-organization deployment (`config/secrets*.yml` supports per-organization `webhook_secret`, e.g. `config/secrets.development.shopify.yml`), each org has its own webhook secret: [7](#0-6) 

This is the exact bug-class analog from the report: the field the signature verification is keyed on (`repository.owner.login`, used to choose the secret / "authenticate the organization") is not the field the write path acts on (`repository.full_name`, used to choose the `Stack`/repository to sync). Just as `liquidatorNFTClaim()` trusted an unvalidated `params.endTime` disconnected from the actual Seaport auction state, this controller trusts an unvalidated `repository.owner.login` disconnected from the `repository.full_name` actually operated on, while both live in the same attacker-supplied, merely HMAC-wrapped JSON body.

An attacker who legitimately controls a repository/organization already registered as a Stack in the same Shipit instance (and therefore knows/can obtain that org's `webhook_secret`, e.g. by having repo admin rights to configure the GitHub App webhook for their own org) can craft a JSON body where:
- `repository.owner.login` = their own org (so `Shipit.github(organization: ...)` selects their own webhook secret and the HMAC check they compute over this exact body succeeds), and
- `repository.full_name` = a **different** organization/repository that also has a `Stack` configured in the same Shipit install.

Because `PushHandler#stacks` resolves via `Repository.from_github_repo_name(repository_name)` using `repository.full_name`, the forged push event is routed to the victim's Stack, invoking `stack.sync_github(expected_head_sha: params.after)` — a write into a Stack the attacker does not own, using only credentials proving control of an unrelated GitHub org.

### Impact Explanation
This crosses a repository-ownership authentication boundary: an actor authenticated only for repository/org A is able to trigger a `GithubSyncJob` (`app/jobs/shipit/github_sync_job.rb`) against Stack B, forcing commit-fetch/sync of an attacker-chosen `expected_head_sha`, and can influence continuous delivery through `CacheDeploySpecJob.perform_later` and downstream deploy triggers keyed off the resulting HEAD state. This is a cross-repository state mutation not permitted by the correct security model (webhook secret should authorize actions only on the org/repo it belongs to), matching the "cross-repository writes" impact category.

### Likelihood Explanation
Requires the attacker to already control a legitimate GitHub App webhook subscription for at least one organization onboarded to the same Shipit instance (a realistic scenario for any Shipit deployment serving multiple teams/orgs with per-org GitHub Apps, as explicitly supported by `config/secrets.development.shopify.yml`). No GITHUB_TOKEN, ApiClient token, or Shipit session is required — only the ability to send an HTTP POST with a self-signed payload, since HMAC verification only proves membership in "some known org," not ownership of the specific repo referenced in the body.

### Recommendation
After `verify_signature` succeeds, re-derive and cross-check that the organization selected for signature verification (`repository_owner`) matches the owner segment of `repository.full_name` (and of `organization.login` if both are present) before dispatching to handlers. Reject the request (422) on mismatch. Handlers should not trust `repository.full_name` independently of the org used for cryptographic verification.

### Proof of Concept
1. Shipit is configured with two GitHub orgs, `attacker-org` and `victim-org`, each with its own Stack and `webhook_secret` (per `config/secrets.development.shopify.yml` schema).
2. Attacker computes `sha1=HMAC(attacker-org secret, raw_body)` for a JSON payload where:
   - `repository.owner.login = "attacker-org"`
   - `repository.full_name = "victim-org/victim-repo"`
   - `ref = "refs/heads/master"`, `after = "<attacker-chosen-sha>"`
3. POST to `/github/webhooks` with header `X-Github-Event: push` and `X-Hub-Signature: sha1=<computed>`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and validates the signature successfully against the attacker's own known secret (`lib/shipit/github_app.rb#verify_webhook_signature`).
5. `PushHandler#stacks` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")`, mutating the victim Stack the attacker does not control.

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
