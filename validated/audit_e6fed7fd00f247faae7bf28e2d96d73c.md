### Title
Webhook signature verification is bound to an organization derived from `params`, while the payload actually processed comes from `request.raw_post` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification based on `repository_owner`, which is read from Rails' `params` object. The actual event payload that gets dispatched to handlers in `create` is a **separate** parse of `request.raw_post`. These two are not guaranteed to describe the same organization/repository, so an attacker can make the signature check pass against one (unsigned/no-secret) organization while the handlers act on a payload that impersonates a completely different, victim repository.

### Finding Description
`repository_owner` is computed from Rails' `params`: [1](#0-0) 

`verify_signature` looks up the GitHub App for that owner and verifies the HMAC over `request.raw_post`: [2](#0-1) 

Crucially, `verify_webhook_signature` short-circuits to `true` whenever the resolved organization has no configured `webhook_secret`: [3](#0-2) 

Sample/default configs frequently leave `webhook_secret` unset (`nil`): [4](#0-3) 

Meanwhile, `create` re-parses the raw body independently and hands that parsed hash to the event handlers: [5](#0-4) 

Rails' `params` for a request is built by merging `request_parameters` (JSON/form body) with `query_parameters`, with query-string values taking precedence on conflicting keys, and then `path_parameters` on top of that. This means an attacker can send:
- A JSON body (verified against `request.raw_post`) that actually targets the **victim** repository/org (e.g. `repository.owner.login = "victim-org"`), and
- A conflicting query-string parameter such as `?repository[owner][login]=attacker-org`, which only affects what `params.dig('repository','owner','login')` returns.

`repository_owner` then resolves to `attacker-org`. If `attacker-org` is any configured organization whose `webhook_secret` is blank/unset (a supported, and in samples default, configuration), `verify_webhook_signature` returns `true` unconditionally — the signature is never actually checked against the bytes that will be processed. `create` then dispatches the *victim-org* payload from `raw_post` to `Shipit::Webhooks.for_event(event)` handlers (e.g. `PushHandler`, `StatusHandler`), which act as if GitHub had legitimately delivered that event for the victim repository.

The binding broken: **organization that authenticated the webhook == organization/repository whose payload is written by the handlers**. This equality fails because the org used for verification is taken from `params` (attacker-influenceable via query string) while the payload acted upon is `request.raw_post` (attacker fully controls its content, e.g. victim org name, sha, state).

### Impact Explanation
`StatusHandler` writes/updates commit statuses that feed into `Commit#deployable?`/merge-queue and deployability checks (exercised in `test/controllers/webhooks_controller_test.rb:42-58`, which shows `status_master` payloads directly mutate `commit.statuses`). By forging a `status` (or `push`/`check_suite`, etc.) event for a victim repository while routing verification to an unrelated, secret-less organization, an unprivileged attacker can inject fabricated CI/commit-status data into a victim stack's commit history, which is subsequently used to greenlight deploys/merges (`Commit#deployable?`). This can result in an unauthorized deploy being triggered against a stack the attacker has no legitimate access to, which is one of the defined Critical impacts.

### Likelihood Explanation
This requires: (1) at least one configured GitHub organization in `Shipit.github_app_config` with a blank `webhook_secret` (shown to be a default/sample configuration, and a supported operational choice for engines that don't need webhook auth for a given org), and (2) knowledge of the victim stack's repository slug/owner (public information). No credentials, GitHub App keys, or privileged Shipit access are required — the request is an ordinary unauthenticated POST to the public `/webhooks` endpoint.

### Recommendation
Compute `repository_owner` from the same parsed `raw_post` payload that is later dispatched to handlers (i.e., parse once, reuse the parsed hash for both signature-org selection and event dispatch), rather than relying on Rails' merged `params`. Additionally, consider rejecting/logging webhooks when the resolved organization has no `webhook_secret` configured instead of silently treating them as verified.

### Proof of Concept
1. Configure two orgs in `secrets.github`: `attacker-org` (no `webhook_secret`) and `victim-org` (has a `webhook_secret`, is a tracked Shipit stack).
2. Send:
```
POST /webhooks?repository[owner][login]=attacker-org HTTP/1.1
Content-Type: application/json
X-Github-Event: status

{"repository":{"owner":{"login":"victim-org"}}, "sha":"<victim-sha>", "state":"success", ...}
```
3. `repository_owner` resolves to `attacker-org` (from query params) → `verify_webhook_signature` returns `true` because `attacker-org` has no secret.
4. `create` re-parses `request.raw_post`, which targets `victim-org`/`<victim-sha>`, and dispatches it to `StatusHandler`, forging a passing CI status on the victim's commit without ever validating a signature tied to `victim-org`'s secret. [6](#0-5)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-62)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** config/secrets.development.shopify.yml (L6-10)
```yaml
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
```
