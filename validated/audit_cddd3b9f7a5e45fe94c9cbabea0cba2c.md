### Title
Webhook signature verification key is selected from an unverified payload field, allowing cross-organization/cross-repository event forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App configuration (and therefore which HMAC `webhook_secret`) to verify the request signature against by reading `repository.owner.login` (or `organization.login`) straight out of the *unverified* JSON body, before the signature has been checked. [1](#0-0)  The `repository`/`organization` fields used for the security decision are not the same fields the downstream webhook handlers use to decide which `Stack`/repository to write to (`repository.full_name`), so an attacker who legitimately controls one Shipit-configured GitHub organization (and therefore genuinely knows its `webhook_secret`) can forge a signature that Shipit will accept, while embedding an unrelated victim organization's repository in the same payload.

### Finding Description
Shipit can be configured with multiple GitHub Apps/organizations, each with its own `webhook_secret` (confirmed by the multi-org fixture `test/dummy/config/secrets_double_github_app.yml`). Signature verification is:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

`verify_webhook_signature` just checks `HMAC(secret, raw_post) == signature` for whatever `secret` belongs to the organization named in `repository_owner`:

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  algorithm, signature = signature.split("=", 2)
  return false unless algorithm == 'sha1'
  SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
end
``` [3](#0-2) 

Because `repository_owner` is read from the same body that is being signed/verified, an attacker who is the legitimate admin of one org registered with Shipit (Org A) knows Org A's real `webhook_secret` (GitHub shows it to whoever configures the webhook). The attacker can craft an arbitrary JSON body where:
- `repository.owner.login` = `"org-a"` (selects Org A's known secret for verification), and
- `repository.full_name` = `"victim-org/victim-repo"` (the field actually consumed by the event handlers/`GithubSyncJob` to select which `Stack` to act on).

Signing that body with Org A's own secret produces a signature `verify_signature` will accept, since it only checks the HMAC against the org named in the unverified body — it never confirms that the organization used for verification matches the organization/repository the handlers subsequently operate on. The existing test suite already demonstrates that the push handler resolves the target purely by `repository.full_name` in the body, independent of the org used for verification:

```ruby
test "create github repository which is not yet present in the datastore" do
  request.headers['X-Github-Event'] = 'push'
  unknown_repo_payload = JSON.parse(payload(:push_master))
  unknown_repo_payload["repository"]["full_name"] = "owner/unknown-repository"
  ...
  post :create, body: unknown_repo_payload, as: :json
end
``` [4](#0-3) 

This is exactly the binding mismatch called out in the rules: "an organization that authenticated versus the repository that is written." The equality that should hold is `organization_used_for_signature_verification == organization_owning_the_repository_acted_upon`; the code never enforces it.

### Impact Explanation
An attacker who legitimately controls any single GitHub organization onboarded into a multi-org Shipit instance can forge webhook events attributed to any other repository/organization tracked by that instance. Depending on which handler processes the event (`push` → `GithubSyncJob`, `status`, `check_suite`, `membership`, `pull_request`, etc.), this can inject fabricated commits/status/check-run data into a victim's `Stack`, fabricate team memberships, or otherwise corrupt state for repositories the attacker has no legitimate access to — i.e., a cross-repository write achieved purely by exploiting the trust binding gap, without ever needing the victim organization's real webhook secret.

### Likelihood Explanation
Requires a Shipit deployment configured with more than one GitHub organization/App (a documented and tested configuration, see `test/dummy/config/secrets_double_github_app.yml`) and an attacker who administers one of those organizations well enough to read its `webhook_secret` — no privileged Shipit account or GitHub token is required, only ordinary admin access to their own onboarded org, which is the normal, expected level of trust for "an org that can register a webhook," not a privileged Shipit role.

### Recommendation
Derive the organization used to select the verification secret independently of attacker-modifiable payload content — e.g., resolve it from the target `Stack`/`Repository` record that will actually be acted upon (looked up by `repository.full_name` and cross-checked against its known, stored owner) rather than trusting `repository.owner.login`/`organization.login` taken directly from the unverified body, or require the request's resolved owner and the payload's target-repository owner to match before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `org-a` (attacker-administered) and `victim-org` (tracked target), following the pattern in `test/dummy/config/secrets_double_github_app.yml`.
2. Attacker, as an admin of `org-a`, knows `org-a`'s `webhook_secret` (it is shown when configuring the webhook on their own org).
3. Attacker builds a `push` payload:
```json
{
  "repository": { "owner": { "login": "org-a" }, "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>"
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(org-a-secret, body)`.
5. POSTs to `/webhooks` with `X-Github-Event: push`. `repository_owner` resolves to `org-a`, `Shipit.github(organization: 'org-a')` returns Org A's app, `verify_webhook_signature` succeeds (the attacker computed a valid HMAC for that secret). [2](#0-1) 
6. `Shipit::Webhooks.for_event('push')` handlers run against the full, attacker-crafted `params`, resolving the target stack via `repository.full_name = "victim-org/victim-repo"` and enqueuing a sync/write against that repository — as shown by the existing test pattern that swaps `repository.full_name` freely without affecting signature handling. [5](#0-4)

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

**File:** test/controllers/webhooks_controller_test.rb (L12-21)
```ruby
    test "create github repository which is not yet present in the datastore" do
      request.headers['X-Github-Event'] = 'push'
      unknown_repo_payload = JSON.parse(payload(:push_master))
      unknown_repo_payload["repository"]["full_name"] = "owner/unknown-repository"
      unknown_repo_payload = unknown_repo_payload.to_json

      assert_nothing_raised do
        post :create, body: unknown_repo_payload, as: :json
      end
    end
```

**File:** test/controllers/webhooks_controller_test.rb (L23-32)
```ruby
    test ":push with the target branch queues a GithubSyncJob" do
      request.headers['X-Github-Event'] = 'push'

      parsed_body = JSON.parse(payload(:push_master))
      expected_head_sha = parsed_body["after"]

      assert_enqueued_with(job: GithubSyncJob, args: [stack_id: @stack.id, expected_head_sha:]) do
        post :create, body: parsed_body.to_json, as: :json
      end
    end
```
