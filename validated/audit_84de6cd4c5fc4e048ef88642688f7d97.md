### Title
Webhook Signature Verification Is Bound to an Attacker-Controlled Organization Claim, Not to the Repository the Payload Actually Mutates - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate a webhook against by reading the organization name straight out of the **unverified** JSON body, then only checks the HMAC against that self-declared organization's secret. Nothing ties the *authenticated* organization to the *repository* (`repository.full_name`) that downstream handlers actually act on. In a multi-organization Shipit deployment (a first-class, documented configuration) this breaks the intended binding: `organization that authenticated == repository that is written`.

### Finding Description
`verify_signature` derives the signing key purely from payload content: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
```

and `repository_owner` is taken directly from the attacker-supplied JSON, with no cross-check against anything already trusted server-side: [2](#0-1) 

```ruby
def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit::GitHubApp#verify_webhook_signature` then simply HMACs the raw body with whatever `webhook_secret` is configured for that self-declared organization: [3](#0-2) 

Shipit explicitly supports hosting multiple, independently-administered GitHub organizations from a single instance, each with its **own** `app_id`/`webhook_secret` (per `docs/setup.md`, "Using Multiple GitHub Applications" and `config/secrets.development.example.yml`). An organization admin legitimately knows their own org's `webhook_secret` (they configured it when creating their GitHub App). Because the field used to pick the verification secret (`repository.owner.login`) and the field handlers use to locate the target repository/stack (`repository.full_name`) are two independent, attacker-controlled fields inside the same unauthenticated body, nothing stops an attacker from setting:
- `repository.owner.login = "OrgA"` (their own org, whose secret they know) so the HMAC check passes, while
- `repository.full_name = "OrgB/some-repo"` (a repository belonging to a different, unrelated organization also hosted on the same Shipit instance).

The signature check therefore only proves "someone who knows OrgA's secret sent this," not "this payload legitimately describes an OrgA (or even the referenced) repository." Downstream event handlers (e.g. push/status handlers) key off `repository.full_name` to resolve the `Stack`/`Repository`/`Commit` to mutate, meaning an attacker with legitimate control of one tenant organization's webhook secret can forge push/status/check_suite events that are processed as if they originated from GitHub for a completely different organization's stack.

This is a direct structural analog of the reported bug: the check (`preCheck`/`postCheck` validating hook initialization, here HMAC validating "organization X sent this") never confirms that the entity being authenticated (`msg.sender` / the declared `repository_owner`) is the same entity the privileged action is performed on behalf of (session key owner / the actual `repository.full_name` being written).

### Impact Explanation
Handlers acting on the forged payload can create commit statuses, sync commits (`GithubSyncJob`), and affect deployability/lock state for a `Stack` belonging to an organization the attacker does not control, mapping to "escalation ... unauthenticated read of stack state" and potentially contributing to an unauthorized deploy/rollback trigger for a cross-organization stack, since Shipit's continuous-delivery and safety checks rely on commit/status data ingested through these same webhook handlers.

### Likelihood Explanation
Requires only that the target Shipit instance is configured with multiple GitHub organizations (a documented, supported configuration) and that the attacker controls one of those organizations well enough to read its own `webhook_secret` — no privileged Shipit account, `ApiClient` token, or GitHub App private key is needed, and no interaction with the honest organization is required.

### Recommendation
Do not select the verification secret from unverified payload content. Instead:
1. Verify the signature against every configured organization's secret (or use a per-organization webhook endpoint/path) and only proceed with an organization match confirmed independently of payload content.
2. After signature verification, assert that `repository.full_name`'s owner matches the organization whose secret verified the signature before dispatching to handlers; reject mismatches.

### Proof of Concept
1. Attacker registers/administers a GitHub App on `OrgA` on a Shipit instance also tracking `OrgB/target-repo`, and knows `OrgA`'s `webhook_secret`.
2. Attacker crafts a `push` (or `status`) JSON body with `repository.owner.login = "OrgA"` and `repository.full_name = "OrgB/target-repo"`, `after`, `sha`, etc. pointing at a chosen commit.
3. Attacker computes `X-Hub-Signature: sha1=HMAC(OrgA_webhook_secret, body)` and POSTs to `/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: "OrgA")`, verifies successfully, and the request proceeds to `Shipit::Webhooks.for_event('push').each { |handler| handler.call(params) }`, which resolves `OrgB/target-repo`'s `Stack`/`Commit` from `repository.full_name` and processes the forged event as if GitHub had sent it — despite the signature never having been produced by anyone with access to `OrgB`'s credentials.

*Note: I was unable to load `app/models/shipit/webhooks/handlers/push_handler.rb`, `app/models/shipit/webhooks/handlers/handler.rb`, and `app/models/shipit/repository.rb` in this session (tool errors on the final iteration) to confirm the exact field(s) used to resolve the target `Stack`/`Repository` from the payload. Based on prior search results (test fixtures/tests referencing `repository.full_name` and `GithubSyncJob` keyed off push payload commit data), handler-side repository resolution appears to use `repository.full_name` independently of the `repository_owner` used for signature selection, but this specific line-level linkage should be confirmed by a follow-up session with full file access.*

### Citations

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
