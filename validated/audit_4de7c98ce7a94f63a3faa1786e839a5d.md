### Title
Webhook signature verification keys off attacker-controlled `repository_owner`, allowing cross-org webhook forgery regardless of the `sha1`-only restriction - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to verify against using `repository_owner`, which is read independently from `params.dig('repository','owner','login')` (or the top-level `organization.login`), while the actual repository that gets mutated is resolved later from `params['repository']['full_name']`. Because nothing enforces that `repository.owner.login` matches the owner encoded in `repository.full_name`, an attacker can pick an org with no configured `webhook_secret` for `repository_owner` while pointing `full_name` at a different, secret-protected org's repo. `GitHubApp#verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank, so no HMAC or algorithm check ever runs on that path, making the `sha1`-only restriction (`return false unless algorithm == 'sha1'`) irrelevant to the bypass.

### Finding Description
Broken binding: verifying-org (`repository_owner`, used to select `Shipit.github(organization: repository_owner)`) is assumed to equal the repository-owning org encoded in `repository.full_name`, i.e. `repository_owner == full_name.split('/').first`. Nothing enforces this equality.

Code path:
- `app/controllers/shipit/webhooks_controller.rb:24-30` — `verify_signature` does `github_app = Shipit.github(organization: repository_owner)` then `github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)`.
- `app/controllers/shipit/webhooks_controller.rb:59-62` — `repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`, both fully attacker-supplied JSON fields, independent of `repository.full_name`.
- `lib/shipit/github_app.rb:76-83` — `verify_webhook_signature` returns `true` unconditionally `unless webhook_secret` (line 77), i.e. if the resolved org has no secret configured, no signature check of any kind (sha1 or otherwise) occurs.
- Handlers under `app/models/shipit/webhooks/handlers/**` (e.g. `pull_request/opened_handler.rb`, `closed_handler.rb`) subsequently locate/mutate the target `Repository`/`Stack` using `params['repository']['full_name']`, not `repository_owner`.

Exploit flow: attacker sends `POST /webhooks` with a body containing `"repository": {"full_name": "victim-org/repo", "owner": {"login": "attacker-controlled-no-secret-org"}}`. `repository_owner` resolves to the no-secret org, `Shipit.github(organization: ...)` returns that org's `GitHubApp` instance with `webhook_secret` nil, `verify_webhook_signature` short-circuits to `true` regardless of the `X-Hub-Signature` header content (any value, or none at all), and the handler then acts on `victim-org/repo`'s stack.

Why the `sha1`-restriction is a red herring: a direct attempt to defeat the victim org's HMAC (e.g. `X-Hub-Signature: sha256=<anything>` or a header with no `=`) against `repository_owner = victim-org` is correctly rejected — `algorithm` becomes `'sha256'` or `nil`, `return false unless algorithm == 'sha1'` fires, and `verify_webhook_signature` returns `false`, yielding `head(422)`. But this restriction only matters when `webhook_secret` is present for the resolved org. The substitution attack never reaches that check at all because the "resolved org" is the attacker-chosen no-secret org (line 77's early `return true`), so the `sha1`/HMAC logic is never exercised. Existing guards (`drop_unhandled_event`, `check_if_ping`, `GithubOrganizationUnknown` rescue) do not validate consistency between `repository.owner.login`/`organization.login` and `repository.full_name`, and no model validation on `Repository`/`Stack` enforces this at handler time either.

### Impact Explanation
An unauthenticated attacker can forge webhook events (pull_request opened/closed/labeled, push, etc.) attributed to any repository whose full_name they know, as long as some org configured in the Shipit instance lacks a `webhook_secret` (or is otherwise resolvable without one), by simply mismatching `repository.owner.login` from `repository.full_name`. This lets an attacker mutate a victim org's repository/stack state (labels, PR-driven stack updates, merge/close events depending on registered handlers) without ever needing to forge an HMAC. This is a cross-tenant authentication bypass: Critical, matching "a payload for one repository mutating another's stack" and "authentication bypass (forged webhook ... accepted)". It is repeatable against any repository whose `full_name` is known, for every request, as long as the attacker-named org resolves and lacks a secret.

### Likelihood Explanation
Preconditions: the Shipit instance must have at least one configured GitHub org with no `webhook_secret` set (or the attacker must otherwise get `Shipit.github(organization: ...)` to resolve to a no-secret config) while another org is secret-protected. No Shipit credentials, sessions, or GitHub secrets are required — only knowledge of the target's `full_name` and an org name that resolves without a secret. Attacker cost is a single crafted, unsigned HTTP POST to `/webhooks`; fully feasible and repeatable at will.

### Recommendation
Bind the verification org to the actual repository owner, not an independently attacker-suppliable field: derive the org used for `Shipit.github(organization: ...)` strictly from `repository.full_name.split('/').first`, and reject the request (422) if `repository.owner.login`/`organization.login` disagree with `full_name`'s owner segment. Additionally, do not allow `verify_webhook_signature` to trivially return `true` for orgs without a configured secret if any other configured org enforces one — require every org to either enforce HMAC verification or explicitly opt out, rather than silently trusting missing configuration.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual additions)

test "sha256 signature against secreted org is rejected" do
  Shipit.stubs(:github).with(organization: 'secreted-org').returns(
    Shipit::GitHubApp.new('secreted-org', webhook_secret: 'shhh')
  )
  post :create, params: {}, body: '{"repository":{"owner":{"login":"secreted-org"},"full_name":"secreted-org/repo"}}',
       headers: { 'X-Github-Event' => 'pull_request', 'X-Hub-Signature' => 'sha256=deadbeef' }
  assert_response 422
end

test "cross-org substitution bypasses signature check entirely" do
  Shipit.stubs(:github).with(organization: 'attacker-org').returns(
    Shipit::GitHubApp.new('attacker-org', {}) # no webhook_secret configured
  )
  post :create, params: {}, body: '{"repository":{"owner":{"login":"attacker-org"},"full_name":"secreted-org/repo"}}',
       headers: { 'X-Github-Event' => 'pull_request' } # no signature header at all
  assert_response 200
  # assert secreted-org/repo's stack/repository record was mutated by the handler
end
```
Both sides of the equality `repository_owner == full_name.split('/').first` are checked: in the first test they match and HMAC correctly blocks a forged sha256/no-`=` signature; in the second test they diverge (`attacker-org` vs `secreted-org`) and the request still succeeds, proving the `sha1` restriction is irrelevant to the underlying cross-org bypass. [1](#0-0) [2](#0-1)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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
