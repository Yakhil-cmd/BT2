### Title
Webhook organization selected for signature verification is not bound to the repository the event actually writes to - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` chooses which GitHub App/organization's `webhook_secret` to validate an incoming webhook against using an attacker-influenced field of the *same* unauthenticated JSON body it is about to verify, rather than a channel independent of that body. The equality the engine needs to hold is: `organization whose secret validated the signature == organization that owns the repository the payload subsequently mutates`. Because both values are read from the same raw, not-yet-verified JSON, an operator who legitimately controls the GitHub App installation for one tenant organization in a multi-org Shipit deployment can craft a payload where `repository.owner.login` (used to pick the secret) differs from the repository actually referenced/acted upon by the event handlers, allowing them to forge events for a stack belonging to a different organization on the same Shipit instance.

### Finding Description
`verify_signature` resolves the app/secret to check the signature against like this: [1](#0-0) 

and: [2](#0-1) 

`repository_owner` is read directly out of the untrusted, not-yet-verified JSON body (`params.dig('repository', 'owner', 'login')`), and `Shipit.github(organization: repository_owner)` is used purely to pick which per-organization `webhook_secret` to HMAC-check the raw body against. The signature check only proves "whoever sent this byte sequence knows the secret configured for the organization named in `repository.owner.login`" — it says nothing about whether the rest of the payload (in particular the `repository.full_name`, used downstream by handlers such as the push/status/check_suite handlers to locate the `Stack`/`Repository` record to act on) actually belongs to that same organization. Multi-tenant setups are an explicitly documented and supported configuration, with a distinct `webhook_secret` per organization: [3](#0-2) 

Since GitHub's HMAC only certifies "this exact byte string was produced by someone holding organization X's secret," and Shipit derives *which* secret to check purely from a field inside that same string, nothing stops the sender (who controls organization X's GitHub App/webhook configuration) from putting a `repository.owner.login` of `X` (so the secret check passes) while other repository fields consumed by the event handlers point at a different organization's repository/stack.

### Impact Explanation
If confirmed against the concrete handler code, this allows a party who administers the GitHub App/webhook for one tenant organization on a shared Shipit instance to inject forged `push`, `status`, or `check_suite` webhook events that are accepted as authentic and processed against a *different* organization's stack — e.g. triggering `GithubSyncJob` for a foreign repository, writing fabricated commit `Status` records, or manipulating check-run/CI state that downstream deploy gating relies on. That constitutes a cross-repository/cross-tenant write and can influence which commits look deployable on a stack that the attacker does not otherwise have any privilege over, which is an authorization boundary the per-organization `webhook_secret` model is meant to enforce.

### Likelihood Explanation
Exploitability strictly requires the attacker to control (i.e., know the `webhook_secret` of) at least one organization's GitHub App configured on the shared Shipit instance — this is expected for any legitimate tenant administrator in a multi-org deployment, not a privileged Shipit account. I was not able to fully confirm, within this session, exactly how the push/status/check_suite handlers key their `Stack`/`Repository` lookup (attempts to read `app/models/shipit/webhooks/handlers/push_handler.rb` and `handler.rb` failed due to a tool error), so I cannot state with certainty whether those handlers key lookups off `repository.full_name` independently of `repository.owner.login`, or whether they re-derive the owner solely from the same `owner.login` field already used for signature selection (which would close this gap). This is the missing piece needed to fully validate exploitability.

### Recommendation
Do not derive the organization used for signature verification from a field that can diverge from the repository ultimately acted upon. Either (a) enforce that `repository.full_name`'s owner segment matches `repository.owner.login`/`organization.login` before proceeding, or (b) resolve the target `Stack`/`Repository` first from a value cryptographically bound 1:1 to the verified organization, and reject the webhook if the repository the handlers would act on does not belong to the same organization whose secret validated the signature.

### Proof of Concept
Could not be fully constructed/verified: confirming exploitability requires inspecting `app/models/shipit/webhooks/handlers/push_handler.rb` and `app/models/shipit/webhooks/handlers/handler.rb` (which define how `Stack`/`Repository` are looked up from the payload) to determine whether they trust `repository.full_name` independently of `repository.owner.login`. I was unable to retrieve those file contents in this session (tool read errors), so this analog should be treated as unconfirmed pending that verification, though the org-selection logic in `webhooks_controller.rb` itself is confirmed as described above.

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
