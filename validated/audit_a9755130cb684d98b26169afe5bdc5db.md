### Title
Webhook signature verified against the organization *claimed in the payload*, not the organization owning the repository actually acted upon - allowing cross-organization webhook forgery ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate the `X-Hub-Signature` against by reading `repository.owner.login` (or `organization.login`) straight out of the **unverified** request body. That same untrusted body is later used verbatim by the event handlers (e.g. `StatusHandler`, `PushHandler`) to decide *which tracked `Stack`/commit* to mutate. Because the "organization whose secret produced a valid signature" and "the repository/commit the handler writes to" are derived from two independent, attacker-controlled sub-fields of the same JSON body, an attacker who knows the `webhook_secret` for *any one* configured GitHub organization can forge a signature that Shipit accepts, while pointing the payload's `repository.full_name` / commit `sha` at a stack belonging to a completely different, unrelated organization.

### Finding Description
`verify_signature` computes `repository_owner` before any authenticity check is performed: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up the App config (and thus the `webhook_secret`) keyed by that self-declared organization name, per the multi-org configuration format documented in `docs/setup.md` (`github: { OrgA: {webhook_secret: ...}, OrgB: {webhook_secret: ...} }`). The signature is only proven to have been generated with *that* organization's secret; nothing ties it to the specific `repository`/`commit` fields that the downstream handler will act on.

Downstream handlers such as the status handler trust the same untrusted body to locate and mutate an existing DB record purely from attacker-supplied fields (`sha`, `state`, `description`, `target_url`, `context`), with no re-validation that the resolved commit's repository is owned by the organization whose secret validated the signature: [3](#0-2) 

The intended security invariant is:
`organization whose webhook_secret verified the signature == organization owning the repository/stack the handler subsequently writes to`

The code instead only enforces:
`organization named in payload.repository.owner.login == organization used to fetch the secret for verification`

These two organizations can diverge because both are read from the same forgeable body, breaking the binding the analog rule describes ("an organization that authenticated versus the repository that is written").

### Impact Explanation
An attacker who legitimately controls (or has obtained the webhook secret for) any single organization configured in Shipit (`github.<org>.webhook_secret` in `secrets.yml`) can send a directly-crafted HTTP POST to `/webhooks` with:
- `X-Github-Event: status` (or `push`)
- `repository.owner.login` = the organization they control (so `verify_signature` fetches and validates against their known secret)
- `repository.full_name`, `sha`, `state`, `target_url`, `description` pointing at a **completely different** tracked `Stack`/commit belonging to another organization present in the same Shipit instance.

Because `StatusHandler` writes the attacker-supplied `state`/`description`/`target_url` directly onto the `Commit` matched by `sha` without checking that the commit's repository belongs to the verified organization, the attacker can inject a fabricated "success" CI status onto an arbitrary commit of a stack they do not own. If that stack's deploy safety gating relies on required GitHub statuses, this enables bypassing CI checks and produces an unauthorized deploy/merge signal for a repository outside the attacker's authorization boundary - a cross-repository write achieved purely through possession of an unrelated organization's webhook secret.

### Likelihood Explanation
Likelihood is Medium: it requires the attacker to know a `webhook_secret` for at least one organization configured in the shared Shipit instance (multi-tenant deployments per `docs/setup.md` "Using Multiple Github Applications"), which is a realistic scenario in shared/self-service Shipit deployments where different teams/orgs each provision their own GitHub App and secret, but none of the other bindings (target org, target repo) are re-checked.

### Recommendation
After signature verification succeeds, re-derive `repository_owner` from the same trusted source used for verification and assert that every repository/commit reference processed by the handler (`repository.full_name`, `organization.login`, commit lookup) is scoped to that verified organization - i.e. reject or ignore payloads whose acted-upon repository does not belong to the organization whose secret validated the signature, rather than trusting the two independently-controlled JSON sub-fields to agree.

### Proof of Concept
1. Shipit is configured with two organizations, `OrgA` (attacker-controlled, secret known: `secretA`) and `OrgB` (victim, secret `secretB`, unknown to attacker), each tracked as `Stack`s.
2. Attacker crafts a `status` event body:
```json
{
  "sha": "<victim commit sha in OrgB/repo>",
  "state": "success",
  "target_url": "https://ci.example.com/fake",
  "description": "forced pass",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(secretA, body)` using their known `OrgA` secret.
4. `verify_signature` reads `repository_owner` = `"OrgA"` (from `repository.owner.login`), calls `Shipit.github(organization: "OrgA")`, verifies successfully against `secretA`.
5. `Shipit::Webhooks.for_event('status')` invokes `StatusHandler`, which looks up the commit by `sha` (belonging to `OrgB/repo`) and creates a `Status` with attacker-controlled `state`/`description`/`target_url`, as exercised in [3](#0-2)  - despite the signature only proving knowledge of `OrgA`'s secret, not `OrgB`'s.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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
