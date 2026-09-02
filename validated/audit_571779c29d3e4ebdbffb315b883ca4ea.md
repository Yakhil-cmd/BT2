### Title
Webhook signature bypass via attacker-controlled `repository.owner.login` selecting an unsecured GitHub App organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and therefore which `webhook_secret`) to validate an incoming webhook against using a value taken directly from the unauthenticated JSON body, before any signature has been checked. Combined with `GitHubApp#verify_webhook_signature` returning `true` unconditionally whenever the selected organization has no `webhook_secret` configured, this breaks the intended binding: *the organization whose secret authenticates the request* vs. *the repository/stack that the webhook event actually mutates*.

### Finding Description
`WebhooksController` extracts the deciding field from the raw, not-yet-verified payload: [1](#0-0) 

This value is used to pick which `GitHubApp` (and its `webhook_secret`) will be used to verify the HMAC, *before* the signature has been validated: [2](#0-1) 

`GitHubApp#verify_webhook_signature` treats a missing `webhook_secret` as an automatic pass: [3](#0-2) 

Shipit explicitly supports multiple GitHub Apps for multiple organizations, each with its own (optional) `webhook_secret`, as documented: [4](#0-3) 
and the app-creation guide even calls the webhook secret "optional": [5](#0-4) 

Because the org used to choose the verification secret (`repository.owner.login` / `organization.login`) is read straight out of the same unauthenticated body that will later be dispatched to handlers, an attacker can set that field to any organization configured in `secrets.yml` that happens to have no `webhook_secret` set (which the docs treat as a normal, supported configuration), while the rest of the payload (branch name, SHA, `repository.full_name`, etc., depending on handler) targets a stack belonging to a *different*, properly secured organization/repository. `PushHandler`, for example, only filters candidate stacks by branch name, not by the organization/owner used for signature selection: [6](#0-5) 

The net effect: the "organization that authenticated" the request (an intentionally unsecured org) is not the same entity as "the repository that is written" (a stack under a different, secured org whose branch name collides), and `verify_signature` never actually authenticates the payload for that second organization's data.

### Impact Explanation
This allows an unauthenticated attacker to inject a forged webhook (`push`, `status`, `check_suite`, `membership`, etc.) that is accepted by Shipit as legitimate, as long as they can find or configure knowledge of one organization in the Shipit deployment that has no `webhook_secret`. This can enqueue `GithubSyncJob` with an attacker-chosen `expected_head_sha` for a stack whose branch name matches, effectively forging a push notification that could trigger continuous-delivery deploys of an attacker-influenced state — an unauthorized deploy path, matching the Critical impact criteria ("unauthorized deploy").

### Likelihood Explanation
Exploitability depends entirely on host configuration: it requires at least one organization/app entry in `secrets.yml` with a blank `webhook_secret` while other organizations are secured — a configuration the documentation itself presents as valid ("optional"). Where that holds (e.g., a legacy/test org left unconfigured, or an admin who skipped the optional field for a low-traffic org), the bypass is trivial and requires no credentials, since `/webhooks` is unauthenticated by design.

### Recommendation
Do not select the verification secret from the same unauthenticated payload that is being verified. Either: (a) require `webhook_secret` to be present for every configured organization (fail closed instead of returning `true` in `verify_webhook_signature` when blank), or (b) bind webhook events to the stack's/repository's actual configured organization derived from trusted, pre-registered repository records rather than from `repository.owner.login`/`organization.login` in the payload, and reject events where the derived organization doesn't match the actual target stack's owner.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.yml`: `secured-org` (has `webhook_secret` set) and `legacy-org` (no `webhook_secret`, i.e., `nil`), per the documented multi-org schema in `docs/setup.md`.
2. Have a `secured-org` stack tracking branch `master`.
3. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "legacy-org" }, "full_name": "legacy-org/whatever" }
}
```
without any valid `X-Hub-Signature` (or an arbitrary one).
4. `WebhooksController#repository_owner` resolves to `legacy-org`; `Shipit.github(organization: "legacy-org")` returns the app whose `webhook_secret` is `nil`; `verify_webhook_signature` returns `true` unconditionally per `lib/shipit/github_app.rb:76-83`.
5. `PushHandler#process` runs against `stacks.not_archived.where(branch: "master")` (per `app/models/shipit/webhooks/handlers/push_handler.rb`), which is not scoped to `legacy-org`, matching the `secured-org` stack and enqueuing `GithubSyncJob` with the attacker's `expected_head_sha`.

Note: I was unable to fully re-verify the exact scoping implementation of `Handler#stacks` (the base class in `app/models/shipit/webhooks/handlers/handler.rb`) before the tool session ended, so whether stack lookup is additionally filtered by repository full name/owner in all handlers should be double-checked in a live session; the signature-bypass mechanism itself (`WebhooksController#repository_owner` → `GitHubApp#verify_webhook_signature`) is confirmed directly from source.

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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```
