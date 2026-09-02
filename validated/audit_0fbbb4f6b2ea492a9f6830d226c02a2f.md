### Title
Webhook signature verification is bound to the wrong organization, letting a forged event for one configured GitHub org act on any repository named in the payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to verify a payload against using `repository_owner`, a value read straight out of the same untrusted payload it is trying to authenticate [1](#0-0) . The handlers that subsequently act on the webhook (creating statuses, enqueuing `GithubSyncJob`, updating stacks, etc.) resolve the target repository independently from other fields of that same payload (e.g. `repository.full_name`), with no requirement that it match the organization whose secret validated the signature [2](#0-1) .

### Finding Description
`Shipit.github(organization: repository_owner)` returns the `GithubApp`/`GithubOrganization` instance for whatever `organization` string is present in `repository.owner.login` (or `organization.login`) inside the attacker-supplied JSON body [2](#0-1) . That instance's `verify_webhook_signature` is then used to accept or reject the whole request:

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [3](#0-2) 

If any organization configured on the instance has no `webhook_secret` set — which `docs/setup.md` explicitly documents as *optional* — every payload claiming to originate from that organization (`repository.owner.login` or `organization.login` set to that org's name) passes verification unconditionally, regardless of the actual `X-Hub-Signature` value [3](#0-2) .

Crucially, the field used to pick the verifying secret (`repository.owner.login`) is not the same field the event handlers use to determine *which repository/stack the event applies to*. `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` passes the entire raw payload through, and handlers (push → `GithubSyncJob`, `status` → commit statuses, etc.) look up the stack by the repository named in the payload, independent of which org's secret authenticated the request [4](#0-3) . This breaks the intended binding: `organization that authenticated == repository that is written`. An attacker who knows that any one configured GitHub App/org has a blank `webhook_secret` (a supported, documented configuration) can set `repository.owner.login` to that unsecured org while pointing the rest of the payload (`repository.full_name`, commit `sha`, `state`, etc.) at a *different*, secured organization's stack.

### Impact Explanation
This allows unauthenticated forgery of GitHub webhook events (`push`, `status`, `check_suite`, `commit_status`, `membership`, etc.) that are supposed to be protected by HMAC signature verification, for repositories belonging to organizations that *do* have a secret configured. Concretely, an attacker can forge a `status`/`commit_status` webhook marking an arbitrary, non-CI-passing commit as green on a target stack; if that stack has continuous deployment enabled, Shipit will treat the commit as deployable and ship it automatically — an unauthorized deploy driven entirely by a spoofed webhook. This matches the "unauthorized deploy" Critical-impact bucket.

### Likelihood Explanation
Requires only one condition outside attacker control: that the Shipit installation is configured with more than one GitHub organization/app and at least one of them has no `webhook_secret` set — a state explicitly permitted as "optional" by the setup documentation and by `GithubApp#initialize`'s handling of a blank `@webhook_secret` [5](#0-4) . No credentials, tokens, or prior access are needed by the attacker; they only need to know (or guess) the name of the secret-less organization and the target repository's identifiers, both of which can be discovered from public GitHub metadata.

### Recommendation
Do not let the verifying organization be chosen from unauthenticated payload data. Either: require every configured organization to have a non-blank `webhook_secret` (removing the `return true unless webhook_secret` bypass), or verify the signature using every configured secret and additionally assert that the organization that validated the signature matches the owner of the repository the handlers will act on before dispatching to `Shipit::Webhooks.for_event`.

### Proof of Concept
1. Shipit is configured with two organizations, e.g. `github: { open-org: { webhook_secret: nil, app_id: ..., installation_id: ... }, secured-org: { webhook_secret: "s3cr3t", ... } }`, matching the documented multi-org format in `config/secrets.development.example.yml`.
2. Attacker POSTs to `/webhooks` with `X-Github-Event: status` and body:
```json
{
  "sha": "<victim-commit-sha>",
  "state": "success",
  "context": "ci/tests",
  "repository": { "owner": { "login": "open-org" }, "full_name": "secured-org/target-repo" }
}
```
with any arbitrary/garbage `X-Hub-Signature` header.
3. `WebhooksController#verify_signature` computes `Shipit.github(organization: "open-org")` and calls `verify_webhook_signature`, which returns `true` immediately because `open-org`'s `webhook_secret` is blank, bypassing signature checking entirely [3](#0-2) .
4. The `status` handler processes the forged payload against `secured-org/target-repo`, creating a fabricated passing status for `<victim-commit-sha>` even though the request was never signed by `secured-org`'s webhook secret, potentially triggering continuous deployment of that commit.

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

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
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
