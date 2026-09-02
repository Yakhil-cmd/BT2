### Title
Webhook signature verification is keyed by attacker-controlled `repository.owner.login`, not the repository being mutated - allowing cross-tenant stack sync (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to validate the request against using `repository_owner`, a value taken directly from the untrusted JSON body (`payload.dig('repository','owner','login')`). If that named organization has no `webhook_secret` configured, `GitHubApp#verify_webhook_signature` returns `true` unconditionally, and the request is dispatched to handlers that act on `repository.full_name`, which can name a completely different organization's stack.

### Finding Description
The broken binding: the organization whose secret is checked, `repository_owner = payload.dig('repository','owner','login')`, is asserted to equal the organization that owns the stack actually mutated by the handler, `payload.dig('repository','full_name').split('/').first`. Nothing in the code enforces this equality.

Code path:
- `verify_signature` resolves `github_app = Shipit.github(organization: repository_owner)` [1](#0-0) 
- `repository_owner` is read straight out of the attacker-supplied JSON body, with no relation enforced to the repository ultimately acted upon: [2](#0-1) 
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever `@webhook_secret` is blank for that organization's config, before any HMAC comparison happens: [3](#0-2) 
- `create` then re-parses the raw body and dispatches to the matching handlers using the event type only, with no re-check of which org was verified: [4](#0-3) 

Attacker request: `POST /webhooks` with header `X-Github-Event: push` and body `{'repository':{'owner':{'login':'attacker-org'},'full_name':'victim-org/victim-repo'},'ref':'refs/heads/master','after':'<sha>'}`, where `attacker-org` is a configured-but-secretless entry in `Shipit.github_apps`. `verify_signature` looks up the `GitHubApp` for `attacker-org`, finds no `webhook_secret`, and short-circuits to `true` regardless of the actual HMAC header. The `PushHandler` (and any other handler keyed off `repository.full_name`) then operates on `victim-org/victim-repo`'s real `Stack` — an organization the request was never authenticated against.

Existing guards do not close this gap: `drop_unhandled_event` only checks event type, not organization identity; `check_if_ping` is irrelevant to `push`; there is no `ExplicitParameters` schema or model validation tying `repository_owner` to `full_name`'s owner segment. The only way this attack fails is if every organization in `Shipit.github_apps` has a `webhook_secret` configured — a deployment/configuration precondition, not a code guarantee.

### Impact Explanation
An attacker who controls (or merely names) an organization entry in `Shipit.github_apps` that lacks a `webhook_secret` can forge webhooks that are processed as if authenticated, and cause `Shipit` to act on any other organization's stack named via `repository.full_name` in the payload (e.g., triggering `stack.sync_github` / `GithubSyncJob`, or other handler-driven mutations for pull_request/status/check_suite events). This is a cross-repository/cross-tenant authentication bypass — Critical severity per the stated impact categories ("a payload for one repository mutating another's stack"). It is fully repeatable against any victim stack whose owner/repo is known, requiring only one misconfigured (secretless) entry anywhere in the multi-tenant `Shipit.github_apps` config.

### Likelihood Explanation
Requires: (1) `Shipit.github_apps` contains at least one organization entry with no `webhook_secret` (a real, plausible misconfiguration in multi-tenant Shipit deployments, e.g., an org added for OAuth/team purposes only, or during onboarding before secret provisioning), and (2) a genuine `Stack` exists for the targeted victim org/repo. No GitHub credentials, no Shipit session, and no knowledge of any secret are needed — only knowledge of the secretless org's login name and the victim's `full_name`. Attacker cost is a single unauthenticated HTTP POST, fully repeatable.

### Recommendation
Verify the webhook signature using the secret belonging to the organization that owns `repository.full_name` (or `organization.login` for org-level events) — not `repository.owner.login` in isolation — and additionally reject/require signature verification to fail closed (not `return true`) when a configured app has no `webhook_secret`, since an app entry lacking a secret should never be treated as a valid signer. At minimum, cross-check that `repository_owner` matches the owner segment of `repository.full_name` before trusting the payload, and treat "no configured secret" as "reject with 422" rather than "verified".

### Proof of Concept
In `test/controllers/webhooks_controller_test.rb`:
1. Stub `Shipit.github_apps` (or the equivalent config accessor) with two entries: `'attacker-org'` (no `webhook_secret`) and `'victim-org'` (with a `webhook_secret`).
2. Create a real `Stack` for `victim-org/victim-repo` (`repository: shipit_repositories(:shipit)` style fixture, or a new one via `Shipit::Stack.create!`).
3. POST to `/webhooks` with header `X-Github-Event: push`, no valid `X-Hub-Signature` (or a garbage one), and body:
   `{'repository':{'owner':{'login':'attacker-org'},'full_name':'victim-org/victim-repo'},'ref':'refs/heads/master','after':'<sha>'}`.
4. Assert response is `200 OK` (not `422`), and `assert_enqueued_with(job: GithubSyncJob, args: [stack_id: victim_stack.id])`, proving the sync was dispatched against `victim-org`'s stack despite the signature only ever being (non-)checked against `attacker-org`'s (absent) secret — i.e., `repository_owner` ('attacker-org') != owner of `full_name` ('victim-org') yet the request was accepted and acted on the victim's stack.

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
