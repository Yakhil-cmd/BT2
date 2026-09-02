### Title
Webhook signature verification silently no-ops when `webhook_secret` is unset, allowing unauthenticated forgery of GitHub events - ([File: lib/shipit/github_app.rb])

### Summary
`Shipit::WebhooksController#verify_signature` delegates signature validation entirely to `GithubApp#verify_webhook_signature`, which returns `true` (i.e., "verified") whenever no `webhook_secret` is configured for the organization, instead of failing closed. Because the templates shipped with Shipit configure `webhook_secret` as blank/`nil` by default, any deployment that does not explicitly set this value processes all inbound GitHub webhook payloads — `push`, `status`, `check_suite`, `membership`, `pull_request` — with **no cryptographic binding at all** between the sender and the payload. This mirrors the `fil_configure` bug class: a component (webhook handlers) acts on attacker-suppliable data that is never actually covered by a verified signature.

### Finding Description
`WebhooksController` runs `verify_signature` as a `before_action`: [1](#0-0) [2](#0-1) 

It resolves the `GithubApp` for the organization named in the untrusted payload (`repository.owner.login` or `organization.login`) and calls `verify_webhook_signature`: [3](#0-2) 

The critical line is:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```
If `webhook_secret` is blank/`nil` for that org's configuration, the method returns `true` unconditionally — no signature is required, no HMAC comparison happens, and the raw request body is accepted as authentic. `create` then dispatches the fully attacker-controlled JSON body to every registered handler for the claimed event type: [4](#0-3) 

The default configuration templates shipped with the engine leave this value empty: [5](#0-4) [6](#0-5) [7](#0-6) 

The binding that should hold is: *"payload accepted by `create`" == "payload whose signature was verified by `verify_webhook_signature`"*. When `webhook_secret` is unset, the left side (all payloads) is a strict superset of the right side (verified payloads — the empty set), because `verify_webhook_signature` treats "no secret configured" as "no verification required" rather than failing closed.

### Impact Explanation
An unauthenticated attacker who merely knows (or guesses) a tracked organization/repository name can POST arbitrary webhook bodies to `/github/webhooks` (or wherever the engine is mounted) with any `X-Github-Event` header and no valid `X-Hub-Signature`. Depending on which handler is invoked this can:
- Forge `status`/`check_suite` events to mark an arbitrary commit as CI-passing, which `MergeRequest#all_status_checks_passed?` and the merge queue (`ProcessMergeRequestsJob`) rely on to trigger `merge!` — leading to an **unauthorized merge**.
- Forge `push` events to manipulate which commits Shipit believes exist/are deployable, potentially triggering continuous deployment of attacker-influenced state.
- Forge `membership` events to create arbitrary `Team`/`User` records.

This crosses the "unauthorized deploy, rollback or merge" threshold in the Critical impact bucket, achieved with zero credentials, tokens, or GitHub access.

### Likelihood Explanation
Likelihood is high in any installation that has not explicitly populated `github.webhook_secret` — which is the literal default in every configuration template and example the engine ships. No repository write access, `ApiClient` token, `webhook_secret`, `api_clients_secret`, GitHub App private key, or privileged Shipit account is required; the attacker only needs network access to the webhook endpoint and the target organization/repository name, both of which are public in an open-source/GitHub context.

### Recommendation
Change `verify_webhook_signature` to fail closed: if `webhook_secret` is blank, reject the request (or require operators to explicitly opt into unsigned webhooks via a distinct, clearly-named flag) rather than treating an absent secret as an automatic pass. Additionally, update setup documentation/templates to make `webhook_secret` mandatory rather than commented out/blank by default.

### Proof of Concept
1. Deploy Shipit using the default `secrets.yml` template, i.e. leave `github.webhook_secret` blank (this is the shipped default).
2. As an unauthenticated attacker, send:
```
POST /github/webhooks HTTP/1.1
Host: shipit.example.com
Content-Type: application/json
X-Github-Event: status

{
  "sha": "<any tracked commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": {"owner": {"login": "<target-org>"}, "full_name": "<target-org>/<target-repo>"}
}
```
No `X-Hub-Signature` header is required.
3. `verify_webhook_signature` returns `true` because `webhook_secret` is `nil`, so the fake "success" status is recorded on the target commit.
4. If the target stack has a merge queue or continuous deployment enabled and that check was a blocking/required status, `ProcessMergeRequestsJob`/continuous delivery will proceed to merge or deploy based on the forged status — with no GitHub credential or Shipit session ever used.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
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

**File:** config/secrets.development.example.yml (L8-11)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
```

**File:** template.rb (L97-113)
```ruby
    production:
      app_name: My Shipit
      secret_key_base: <%= ENV['SECRET_KEY_BASE'] %>
      host: <%= ENV['SHIPIT_HOST'] %>
      redis_url: <%= ENV['REDIS_URL'] %>
      github:
        domain: # defaults to github.com
        app_id: <%= ENV['GITHUB_APP_ID'] %>
        installation_id: <%= ENV['GITHUB_INSTALLATION_ID'] %>
        webhook_secret:
        private_key:
        oauth:
          id: <%= ENV['GITHUB_OAUTH_ID'] %>
          secret: <%= ENV['GITHUB_OAUTH_SECRET'] %>
          # teams: MyOrg/developers # Enable this setting to restrict access to only the member of a team
      env:
        # SSH_AUTH_SOCK: /foo/bar # You can set environment variable that will be present during deploys.
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
