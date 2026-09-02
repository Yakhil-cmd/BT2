### Title
Webhook signature is verified against the organization derived from the payload, but handlers act on a repository/commit reference from the same untrusted payload that is never checked against that organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and thus which `webhook_secret`) to validate the HMAC signature against using a field taken from the same JSON body being verified (`repository.owner.login` / `organization.login`). Once the signature check passes, the event is dispatched to handlers that act on a **different** field of that same payload - `repository.full_name` (or, in `StatusHandler`, no repository field at all, only `sha`). Nothing ties the organization whose secret validated the request to the repository/commit that is actually mutated.

### Finding Description
`verify_signature` computes `repository_owner` from the payload and fetches that organization's `Shipit.github(organization: repository_owner)` app to check the HMAC: [1](#0-0) [2](#0-1) 

`verify_webhook_signature` just HMACs the raw body against that org's `webhook_secret`: [3](#0-2) 

Once verification passes, `create` hands the entire parsed payload to the registered handlers: [4](#0-3) 

Handlers resolve their target stacks using `repository.full_name`, a completely separate JSON field never checked against `repository_owner`: [5](#0-4) 

`StatusHandler` is worse - it doesn't even scope by repository, it looks up commits globally by `sha`: [6](#0-5) 

Because Shipit is designed to be configured for multiple GitHub organizations at once (each with its own independent `webhook_secret`), as shown in the sample config: [7](#0-6) 

any organization that has legitimately connected its own GitHub App to a shared Shipit instance knows its own `webhook_secret` (they configured it). That secret is only proven to authenticate for the "owner" field used in signature selection - it is never proven to authorize writes to the `repository.full_name`/`sha` values used by the handlers. An attacker who administers **their own** onboarded organization can therefore POST directly to `/webhooks` (bypassing GitHub entirely) with:
- `repository.owner.login` = their own org (so `verify_signature` picks their own real secret, which they know, and the HMAC they compute passes)
- `repository.full_name` / `sha` referencing a **different** organization's repository or commit hosted on the same shared instance.

Binding broken: `organization authenticated by signature == organization whose repository/commit is written` — this equality is never asserted anywhere in the request pipeline.

### Impact Explanation
Because `StatusHandler` performs no repository scoping at all (`Commit.where(sha: params.sha)`), an attacker who only controls a webhook secret for their own onboarded org can forge a commit-status event with `state: "success"` for any commit `sha` belonging to any other stack on the shared instance. Commit CI status feeds directly into `deployable?`/CI-gating logic used by deploy triggers and `continuous_deployment`; forging a "success" status for an attacker-chosen commit on a victim stack that has `continuous_deployment` enabled can cause that commit to be automatically deployed - an **unauthorized deploy**, which is explicitly listed as Critical impact. Other handlers (`push`, `pull_request` opened/labeled/reopened/closed) similarly key off attacker-controlled `repository.full_name`, letting the same attacker trigger `sync_github`, and create/archive/unarchive review stacks for repositories they do not own, on a shared Shipit deployment.

### Likelihood Explanation
Requires only that the attacker administers one org that is a legitimate, unprivileged tenant of a shared Shipit instance (a normal, expected configuration per `config/secrets.development.shopify.yml`, which lists multiple independent orgs each with their own `webhook_secret`). No Shipit session, `ApiClient` token, or private key is needed - only the attacker's own webhook secret, which they hold by virtue of having connected their own (unrelated) repository. The request is a direct unauthenticated POST to `/webhooks`, not routed through GitHub, so no GitHub-side controls apply.

### Recommendation
After selecting the organization via `repository_owner` and verifying the signature, positively verify that every repository/commit reference the handler will act on (`repository.full_name`, and for `StatusHandler`, the owning repository of `sha`) belongs to that same, already-authenticated organization before invoking any handler. Do not let handlers resolve their target purely from attacker-suppliable payload fields; instead thread the verified organization identity into `Handler#stacks`/`StatusHandler#process` and reject/ignore events where the two disagree.

### Proof of Concept
1. Attacker legitimately connects "attacker-org" to the shared Shipit instance, and thus knows `attacker-org`'s configured `webhook_secret`.
2. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "<victim commit sha, e.g. from a public PR on victim/repo>",
  "state": "success",
  "repository": { "owner": { "login": "attacker-org" } }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac(attacker-org secret, body)>` and POSTs it to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s app, and the HMAC validates successfully (`app/controllers/shipit/webhooks_controller.rb:24-30`, `lib/shipit/github_app.rb:76-83`).
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) with no relation to `attacker-org` whatsoever, and marks the victim's commit as CI `success`, potentially triggering an automatic deploy on a `continuous_deployment`-enabled victim stack.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** config/secrets.development.shopify.yml (L5-23)
```yaml
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
