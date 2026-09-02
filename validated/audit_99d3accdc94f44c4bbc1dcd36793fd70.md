### Title
Webhook signature verification is keyed off an unauthenticated payload field, allowing cross-organization webhook/commit-status forgery in multi-GitHub-App deployments - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate a webhook's HMAC against by reading `repository_owner` straight out of the *unverified* JSON body, then—once the HMAC checks out—dispatches the *entire* unscoped payload to every registered handler. Nothing binds the organization whose secret produced a valid signature to the `repository`/`sha` fields the handlers actually act on. In a deployment that connects multiple GitHub organizations (a documented, supported configuration), an attacker who legitimately administers *any one* of those organizations can forge a webhook body that names a victim organization's repository/commit while signing it with their own, genuinely-possessed secret.

### Finding Description
`verify_signature` derives the signing key from attacker-controlled data before any authentication has occurred: [1](#0-0) 

`repository_owner` is read directly from the JSON body with no cross-check against the org that actually authenticates: [2](#0-1) 

Once `verify_webhook_signature` returns true for whatever organization `repository_owner` names, the controller hands the *complete, unscoped* payload to the handlers: [3](#0-2) 

`verify_webhook_signature` itself only proves the HMAC matches *some* org's configured secret against the raw body—it says nothing about whether the repository referenced inside that body actually belongs to that org: [4](#0-3) 

Because Shipit explicitly supports multiple independent GitHub organizations pointing at one instance (each with its own `webhook_secret`, as in `secrets_double_github_app.yml` and documented under "Using Multiple Github Applications"), an attacker who is a legitimate owner/admin of *any* connected organization possesses a real webhook secret: [5](#0-4) [6](#0-5) 

The attacker can then:
1. Craft a JSON payload where `repository.owner.login` = their own org (`attacker-org`), but `repository.full_name` / `sha` / `branches` reference a **victim** stack's repository and commit.
2. Sign the exact raw body with `attacker-org`'s real `webhook_secret`.
3. POST it to `/webhooks`. `verify_signature` looks up `repository_owner` = `attacker-org`, fetches `attacker-org`'s `GitHubApp`, and the HMAC check succeeds — because the attacker genuinely signed that body with their own secret.
4. The handler(s) for the declared event (e.g. `status`, `push`, `check_suite`, `membership`) then run against the payload's `repository`/`sha`/`branches` fields, which reference the **victim** org's stack — a binding the signature check never established.

The webhook signature therefore authenticates "this payload was produced by an org that owns *a* configured secret," while the handlers act as if it authenticates "this payload legitimately describes state for the repository named inside it." Those are different repositories/organizations, and the controller never checks that they match — exactly the "organization authenticated vs. repository written" trust binding called out as in-scope.

### Impact Explanation
Handlers dispatched from this endpoint mutate authoritative state used to gate deploys: commit CI status (`status` event, matched by `sha`/repository params as exercised in `webhooks_controller_test.rb`), check-run refresh jobs, and even team/user creation (`membership` event). Forging a passing CI status on a victim commit can satisfy `ci.require` safety gates in `shipit.yml` and enable an **unauthorized deploy** of that commit — the Critical-tier impact defined in scope. At minimum it allows an attacker with no relationship to the victim organization to inject falsified state (status/check-run/PR events) into a victim's stack.

### Likelihood Explanation
Requires only that the attacker legitimately control one GitHub organization connected to a shared, multi-org Shipit deployment (an officially documented configuration) — no Shipit session, API token, or webhook secret theft is needed, satisfying the "unprivileged attacker" requirement. The webhook endpoint is unauthenticated by design (it must accept unsolicited GitHub calls), so the only gate is `verify_signature`, which this flaw defeats via a self-consistent, attacker-signed payload.

### Recommendation
After signature verification succeeds for the org identified by `repository_owner`, explicitly verify that `repository.full_name` (or `repository.owner.login`) inside the verified payload matches a `Repository`/`Stack` actually associated with that same organization before invoking any handler, rejecting mismatches with 422.

### Proof of Concept
1. Attacker owns `attacker-org`, which has its own GitHub App installed on this shared Shipit instance with webhook secret `S_attacker` (per the documented multi-org config).
2. Attacker builds a `status` event JSON body: `{"sha": "<victim_commit_sha>", "state": "success", "context": "ci/required", "branches":[{"name":"master"}], "repository": {"full_name": "victim-org/victim-repo", "owner": {"login": "attacker-org"}}}`.
3. Attacker computes `sha1=HMAC(S_attacker, raw_body)` and sends `POST /webhooks` with `X-Github-Event: status` and `X-Hub-Signature: sha1=...`.
4. `verify_signature` reads `repository_owner` → `"attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and the HMAC check passes (`app/controllers/shipit/webhooks_controller.rb:24-38`).
5. `Shipit::Webhooks.for_event('status')` handlers run against the payload, updating status for `victim-commit_sha`/`victim-org/victim-repo`, even though `victim-org` never authenticated this request.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-10)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
```
