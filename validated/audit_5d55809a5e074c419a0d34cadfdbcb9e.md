### Title
Response-code oracle in `WebhooksController` leaks which orgs lack `webhook_secret` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` calls `verify_webhook_signature`, which unconditionally returns `true` when an organization's `webhook_secret` is blank [1](#0-0) . Combined with the distinct `head(422)` paths for "unknown organization" vs. "signature mismatch," an unauthenticated caller can send crafted `X-Github-Event: push` requests with varying `organization.login`/`repository.owner.login` values and no valid HMAC, and use the resulting HTTP status (`200` vs `422`) to map out exactly which configured orgs have no `webhook_secret` set.

### Finding Description
The binding under test: `response_code(org) == information available only to an authenticated org member`. Before the fix this equality is violated: an unauthenticated internet client fully controls `org` and can read `response_code(org)` directly from the HTTP response, with no session, API token, or webhook secret.

Trace:
1. `before_action :check_if_ping, :drop_unhandled_event, :verify_signature` [2](#0-1) . Ping events short-circuit to `200` before signature checking and thus leak nothing, but a *handled* non-ping event (e.g. `push`) reaches `verify_signature`.
2. `verify_signature` resolves `Shipit.github(organization: repository_owner)`. If the organization has no configured `GitHubApp`, this raises `Shipit::GithubOrganizationUnknown`, caught and turned into `head(422)` [3](#0-2) .
3. If the organization *is* configured, `github_app.verify_webhook_signature` is called. For a configured org with a `webhook_secret`, an attacker without the secret will fail HMAC comparison, again yielding `head(422)` [4](#0-3) .
4. For a configured org *without* a `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally regardless of the signature header supplied [5](#0-4) , so `verify_signature` does not halt the filter chain, and `create` proceeds to run the registered handlers and return `head(:ok)` (`200`) [6](#0-5) .

No component of the request pipeline (`check_if_ping`, `drop_unhandled_event`, `verify_signature`) requires prior authentication, and none of the model validators (`Repository`, `Stack` env/branch format) are involved at this stage — the divergence happens purely in the controller filter chain based on server-side configuration, which is exactly the leak the question describes. This is a genuine, reproducible information-disclosure oracle that requires zero secrets to exploit and differentiates three states (`unknown org` / `configured-with-secret` / `configured-without-secret`) purely by HTTP status code.

### Impact Explanation
The leaked bit (whether a given `organization.login` known to Shipit has a `webhook_secret` configured) by itself does not expose stack state, task output, or credentials — it only reveals a name that already exists in the Shipit host's `secrets.yml`/config, which is not itself secret data. However, it materially reduces the attacker's search space for the separate, more severe signature-bypass vulnerability (a secret-less org accepts a forged `push` payload unconditionally, letting an attacker fabricate commits/trigger `GithubSyncJob` for that org's stacks). Practically, discovering a secret-less org via this oracle and then abusing it is bounded to orgs the operator misconfigured (no `webhook_secret` set) — it does not, by itself, cross-authenticate an attacker into a *properly configured* org's stacks, nor does it leak `github_access_token`, `api_clients_secret`, or deploy secrets. Its severity is best characterized as a low-cost reconnaissance aid for the already-critical secret-less-org bypass rather than a standalone Critical/High primitive.

### Likelihood Explanation
Preconditions: the target Shipit deployment must have at least one organization configured in `Shipit.github` without a `webhook_secret` (an existing misconfiguration, not something this controller can create), and the attacker must know or guess candidate `organization.login` values (often public/guessable, e.g. company GitHub org names). Attacker cost is a handful of unauthenticated HTTP POSTs to `/webhooks` with a `push` (or other handled) event header and varying `organization.login`; no signature, session, or token is required. This is trivially repeatable and scriptable.

### Recommendation
- Make responses to `verify_signature` failures and unknown-organization failures indistinguishable (e.g., always return `422` with an identical body/log level visible only server-side) so config state cannot be inferred by response code alone.
- Treat a missing/blank `webhook_secret` as a hard misconfiguration: refuse to process any webhook for such an org (return `422`/`503`) instead of implicitly trusting unsigned payloads in `GitHubApp#verify_webhook_signature`.
- Add a startup/health check that fails loudly if any configured GitHub org lacks a `webhook_secret`, rather than silently degrading to signature-bypass mode at request time.

### Proof of Concept
In `test/controllers/webhooks_controller_test.rb` style (minitest, no live GitHub):
```ruby
test "response code reveals whether an org has a webhook_secret configured" do
  # Org A: configured, has webhook_secret -> wrong/absent signature => 422
  post shipit.github_webhooks_path,
       params: { organization: { login: "secretful-org" }, repository: { owner: { login: "secretful-org" } } }.to_json,
       headers: { 'X-Github-Event' => 'push', 'Content-Type' => 'application/json' } # no/garbage X-Hub-Signature
  assert_response 422

  # Org B: configured, no webhook_secret -> accepted regardless of signature
  post shipit.github_webhooks_path,
       params: { organization: { login: "secretless-org" }, repository: { owner: { login: "secretless-org" } } }.to_json,
       headers: { 'X-Github-Event' => 'push', 'Content-Type' => 'application/json' } # no X-Hub-Signature at all
  assert_response :ok   # <-- distinguishes it from org A/unknown org purely by status code, with no secret used

  # Org C: not configured at all -> 422 with GithubOrganizationUnknown
  post shipit.github_webhooks_path,
       params: { organization: { login: "unknown-org" } }.to_json,
       headers: { 'X-Github-Event' => 'push', 'Content-Type' => 'application/json' }
  assert_response 422
end
```
Assert both sides of the binding: before the fix, `response_code("secretless-org")` (`200`) is observably distinct from `response_code("secretful-org")`/`response_code("unknown-org")` (`422`), even though the requester supplied no authentication of any kind — violating "response code == info available only to an authenticated org member." After applying the recommendation (uniform `422`/refusal for secret-less orgs), all three requests should return the same status, eliminating the oracle.

### Citations

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L6-6)
```ruby
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature
```

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

**File:** app/controllers/shipit/webhooks_controller.rb (L39-49)
```ruby
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
