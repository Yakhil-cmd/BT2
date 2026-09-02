### Title
Webhook Organization Used for Signature Verification Is Not Bound to the Repository Acted On - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config (and therefore which `webhook_secret`) to validate the HMAC signature against by reading `repository.owner.login` (or `organization.login`) out of the *unverified* JSON body, and only then verifies the raw body against that org's secret. [1](#0-0)  Nothing in this flow cryptographically binds the "organization whose secret authenticated the request" to the "repository the downstream handlers actually act on" — the same JSON body can carry an owner/org used purely to pick a valid secret while other fields (e.g. `repository.full_name`) drive which `Stack`/`Repository` a handler operates on. This mirrors the CSX finding's underlying pattern: a privileged/trust decision (which secret is valid) is made on one field, while the state-changing action is taken based on a different, unauthenticated field in the same payload.

### Finding Description
`verify_signature` does:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

`Shipit.github(organization:)` resolves per-organization config (each org can have its own `webhook_secret`), and the HMAC is checked with `verify_webhook_signature`, which itself is a straightforward `secure_compare` over the raw body using that organization's secret. [3](#0-2)  The signature check does technically cover the whole raw body (so an attacker without the secret cannot forge one), but the *decision of which secret to check against* is derived from a field inside that same untrusted body, and the downstream event handlers (e.g. `push`, `status`, `pull_request` handlers) subsequently key their state changes off other fields of the payload (`repository.full_name`, commit `sha`, PR `number`, etc.) rather than re-validating that the owner used for signature selection matches the repository being mutated.

In a multi-org Shipit deployment (`config/secrets*.yml` supports a `github:` hash keyed by organization, each with its own `webhook_secret`), an attacker who legitimately controls one configured organization (and therefore knows/can compute that organization's `webhook_secret`) can craft a raw JSON payload where:
- `repository.owner.login` / `organization.login` = the attacker's own organization (so `repository_owner` resolves to their org, and they can produce a valid HMAC with their known secret), while
- `repository.full_name`, commit `sha`, `pull_request.number`, etc. reference a **different, victim** organization's repository/stack.

Because `verify_signature` never checks that `repository_owner` equals the actual repository being touched, and the event handlers act purely on other payload fields, this can smuggle a validly-signed webhook (signed with the attacker's own secret) that manipulates state belonging to a repository/stack the attacker does not control.

### Impact Explanation
If exploitable, this breaks the equality "organization that authenticated == repository that is written," which the rules explicitly flag as a valid analog class. Depending on which webhook handler is reached (`push`, `status`, `check_suite`, `pull_request`, `membership`), this could let an attacker influence a victim stack's commit tracking, CI status records, or merge/pull-request bookkeeping for a repository outside their control, using a signature computed from a secret they legitimately possess for an unrelated organization. This does not directly hand over `GITHUB_TOKEN`/`github_access_token`, nor does it require session/API-client credentials, satisfying the engine's threat model of an "unprivileged attacker" (anyone able to send an HTTP POST to `/webhooks`) exploiting a deployment-trust binding gap.

### Likelihood Explanation
Exploitability is conditional and only realistic in **multi-organization** Shipit deployments where different organizations use different `webhook_secret` values and where an attacker legitimately administers at least one such organization (e.g., a shared/multi-tenant Shipit instance, which the engine explicitly supports via the documented multi-org `github:` config). In a single-organization deployment (the common case) there is only one secret, and knowing it already implies broad access, so the binding-mismatch adds no incremental risk. I could not fully verify, within the available tool budget, whether every downstream handler additionally cross-checks `repository.owner.login` against `repository.full_name` before acting (I was unable to inspect `push_handler.rb`, `status_handler.rb`, and `handler.rb` in this session due to tool errors), so it is uncertain whether all handlers are actually reachable/exploitable this way, or whether some independently validate repository identity elsewhere (e.g. via `Repository.from_github_repo_name` uniqueness or stack scoping) that would neutralize the impact.

### Recommendation
- After determining `repository_owner` for secret selection, re-derive the repository/organization actually referenced by the payload (e.g., `repository.full_name`) and assert that its owner matches `repository_owner` before dispatching to handlers; reject mismatches with `422`.
- Alternatively, bind webhook secrets to the specific `Repository`/`Stack` record (not just the org) so a signature can only ever authorize events for that exact repository.
- Add regression tests that POST a validly-signed payload for organization A whose `repository.full_name` points at organization B's repo, and assert the request is rejected.

### Proof of Concept
Conceptual PoC (requires a multi-org Shipit deployment with attacker controlling org `attacker-org`'s webhook secret):
1. Attacker knows `webhook_secret` configured for `attacker-org` (they legitimately administer that org's GitHub App/webhook).
2. Attacker builds a JSON body:
```json
{
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  },
  "sha": "...",
  "state": "success",
  ...
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac(webhook_secret_attacker_org, raw_body)>` and POSTs to `/webhooks` with `X-Github-Event: status` (or `push`).
4. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches that org's `github_app`, and the signature validates successfully against the attacker-crafted body.
5. `Shipit::Webhooks.for_event('status')` handlers run and, per `webhooks_controller_test.rb`'s own test pattern (`:state create a Status for the specific commit`, which locates the target purely via `sha`/`repository` fields merged from `repository_params`), create/update state for `victim-org/victim-repo` using the attacker-controlled `sha`, unaffected by the fact that the signature was computed with `attacker-org`'s secret. [4](#0-3) 

I was not able to fully confirm within this session whether the `status`/`push` handlers include an additional owner-consistency check that would block step 5 (tool errors prevented reading `push_handler.rb`/`status_handler.rb`/`handler.rb` in the final iteration) — this should be verified directly against those files before treating the finding as fully confirmed.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```
