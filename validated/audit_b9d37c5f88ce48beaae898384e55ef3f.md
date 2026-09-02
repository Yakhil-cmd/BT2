Based on my investigation, I was unable to fully load `app/models/shipit/webhooks/handlers/push_handler.rb` and `status_handler.rb` (tool errors on this final iteration), so I cannot cite the exact field the handlers use to resolve a `Stack`/`Repository` from the webhook payload. I can, however, fully confirm the signature-verification code path, and it exposes a concrete binding break consistent with the requested bug class. I'm flagging this uncertainty rather than guessing at unseen file contents.

### Title
Webhook signature verification is keyed off an attacker-controlled `organization`/`repository.owner.login` field that is decoupled from the repository actually acted upon - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App's `webhook_secret` to validate the HMAC against using a value read straight out of the unauthenticated JSON body, before that body has been proven authentic. Because `webhook_secret` is documented as optional per-organization, any tenant configured without one causes `verify_webhook_signature` to unconditionally return `true`, letting an attacker author a payload that "authenticates" as that org while referencing a repository under a different, protected org.

### Finding Description
`repository_owner` is derived from the raw, unverified request body: [1](#0-0) 

This value selects the `GitHubApp` instance whose secret is used for the HMAC check: [2](#0-1) 

`verify_webhook_signature` trivially passes whenever the resolved organization has no `webhook_secret` configured, which the setup docs explicitly call optional: [3](#0-2) [4](#0-3) 

After `verify_signature` passes, the full, attacker-controlled `params` hash (not just the field used to pick the secret) is handed to the event handlers: [5](#0-4) 

The equality that should hold is: *organization whose secret authenticated the request* == *organization/repository the handler subsequently acts on*. Nothing in `verify_signature` ties the two together beyond re-reading the same attacker-supplied `repository.owner.login`/`organization.login` field — a field with no cryptographic binding of its own (the signature only proves the whole raw body was signed by *some* secret, not that `repository_owner` correctly reflects the org that secret belongs to). In a multi-org configuration (explicitly supported, see `test/dummy/config/secrets_double_github_app.yml`), an attacker who can get one org onto the allowlist without a `webhook_secret` (or who can reach any org whose secret is otherwise weak/leaked) can craft a payload where `repository.owner.login`/`organization.login` matches that unsecured org (so the signature check trivially passes), while other payload fields (e.g. `repository.full_name`, commit `sha`, `state`) reference a different, victim stack/repository entirely. I was not able to confirm from the code I could load in this session whether `push_handler.rb`/`status_handler.rb` re-validate that `full_name`'s owner matches `repository_owner`; if they don't (which is the norm for GitHub webhook consumers, since real GitHub payloads always keep these fields consistent), this is directly exploitable.

### Impact Explanation
If the handler resolves the target `Stack`/`Commit` via `repository.full_name` (or similar) without re-deriving/re-checking it against the organization that was actually used for signature verification, an unauthenticated attacker can forge `status` or `push` events for a stack they do not own. Forged `status` events are used by Shipit to gate deploy safety checks, so this could translate into an **unauthorized deploy** (Critical per the rubric). At minimum it allows spoofed commit/CI state for stacks under organizations the attacker has no relationship with, an authentication-boundary violation.

### Likelihood Explanation
Requires only: (1) a Shipit instance configured for more than one GitHub organization (a documented, supported configuration) or one org without a `webhook_secret` (documented as optional), and (2) the ability to send an arbitrary POST to `/webhooks` with a crafted JSON body and a signature computed against the weaker org's secret (which for an org with no secret configured requires no secret knowledge at all). No repository write access, session, or API token is needed.

### Recommendation
Bind the value used to select the verifying secret to the same value used by every downstream handler to resolve the target repository/stack, and reject the request if they diverge. Consider making `webhook_secret` mandatory (removing the "optional" bypass path in `verify_webhook_signature`), and have handlers independently confirm that any repository/organization identifiers in the payload belong to the organization that was cryptographically verified, rather than trusting `repository.full_name` (or similar) at face value.

### Proof of Concept
1. Configure/observe a multi-org Shipit deployment where `OrgB` has no `webhook_secret` set (permitted by `docs/setup.md`).
2. POST to `/webhooks` with header `X-Github-Event: status`, body: `{"organization":{"login":"OrgB"}, "repository":{"owner":{"login":"OrgB"}, "full_name":"OrgA/victim-repo"}, "sha":"<victim-commit-sha>", "state":"success", ...}`.
3. `verify_signature` resolves `repository_owner` to `OrgB`, whose `verify_webhook_signature` returns `true` unconditionally (no secret configured) — no valid `X-Hub-Signature` needed.
4. The full payload (with `full_name` pointing at `OrgA/victim-repo`) reaches `Shipit::Webhooks.for_event('status')` handlers, which — unless independently re-validated (unconfirmed in this session) — would write a forged `Status` for a commit under `OrgA`, an organization the attacker never authenticated against.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```
