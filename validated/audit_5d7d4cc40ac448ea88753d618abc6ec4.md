### Title
Cross-organization webhook forgery via mismatched signature-verification identity and repository-resolution identity - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate a signature with by reading `repository.owner.login` (falling back to `organization.login`) straight out of the **unverified** JSON body. Every event `Handler` then independently resolves *which* `Stack`/`Repository` to act on using a *different* field of that same unverified body — `repository.full_name`. Because the HMAC only proves "this body was signed with organization X's secret," and nothing binds `repository.owner.login` to `repository.full_name` inside that body, an attacker who owns a legitimate GitHub App/webhook integration for one organization on a multi-tenant Shipit instance can forge a webhook that authenticates as their own org but whose `repository.full_name` names a victim organization's repository, causing Shipit to write state (sync a victim stack, create a bogus commit `Status`, etc.) for a repository they do not control.

### Finding Description
`verify_signature` derives the org used for secret lookup purely from the payload: [1](#0-0) [2](#0-1) 

`github_app.verify_webhook_signature` only checks that the raw request body was HMAC-signed with the secret configured for that particular `repository_owner`/organization: [3](#0-2) 

Once the signature passes, `WebhooksController#create` hands the *entire* unverified JSON to the matching `Shipit::Webhooks` handler: [4](#0-3) 

Every handler resolves the target `Stack`(s) via `Handler#stacks`, which uses `repository.full_name` — a field entirely independent of the `repository.owner.login`/`organization.login` field used for signature verification: [5](#0-4) 

`PushHandler` (and similarly `Status`/`CheckSuite`/`PullRequest` handlers) then acts on whatever `Stack`s that `full_name` lookup returns: [6](#0-5) 

This breaks the required binding equality **"organization that authenticated == repository that is written."** The verified party is `repository.owner.login` (org A, whose secret validated the signature); the acted-upon party is `repository.full_name` (attacker-chosen, e.g. `victim-org/victim-repo`). GitHub itself never enforces that these two fields are consistent for a webhook the attacker crafts and signs themselves with their own org's secret — the mismatch is entirely a Shipit-side trust gap, since Shipit assumes the whole body pertains to the org it used for verification.

### Impact Explanation
On a Shipit instance configured with multiple GitHub organizations/apps (`Shipit.github(organization: ...)` supports per-org config), an attacker who administers their own onboarded organization (and therefore has a genuinely working webhook channel/secret for that org — not a stolen credential) can forge a `push`, `status`, or `check_suite` event whose `repository.owner.login` says "attacker-org" but whose `repository.full_name` says "victim-org/victim-repo". Shipit will:
- Trigger `stack.sync_github` for the victim's stack (`PushHandler`), or
- Create a forged `Status` record with attacker-chosen `sha`/`state`/`target_url` on a victim commit (status handler), potentially satisfying deploy/merge-queue gating that depends on GitHub commit status webhooks.

This is a cross-tenant write into a repository/stack the requesting organization does not own, matching the Critical "cross-repository writes" / "unauthorized deploy" impact category, since forged green statuses can enable auto-deploy or merge-queue progression for a victim's commits.

### Likelihood Explanation
Requires a multi-organization Shipit deployment where more than one organization's GitHub App/webhook is configured (a common real-world setup, since `Shipit.github(organization:)` is keyed by org). No stolen secrets, sessions, or API tokens are needed — only the attacker's own legitimately-configured organization webhook. The only "special condition" is running Shipit for more than one org, which is standard for a shared, multi-tenant Shipit instance.

### Recommendation
After signature verification, do not trust `repository.full_name` (or any other repository/org identifying field) independently. Instead, verify that the repository/org resolved for handler dispatch belongs to the same GitHub organization (`repository_owner`) whose secret validated the request, e.g., re-derive `repository_name` only after confirming `payload.dig('repository','owner','login')` (or `organization.login`) matches the organization actually stored against the resolved `Repository`/`Stack`, and reject the event otherwise.

### Proof of Concept
1. Attacker owns/administers GitHub organization `attacker-org`, which has a working GitHub App installed and pointed at the shared Shipit instance (its `webhook_secret` is legitimately known to the attacker as the org owner).
2. Attacker crafts a `push` webhook body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker signs the raw body with `attacker-org`'s webhook secret and POSTs it to `/webhooks`.
4. `verify_signature` reads `repository_owner = "attacker-org"`, fetches `attacker-org`'s secret, and the HMAC validates successfully [1](#0-0) .
5. `PushHandler#stacks` resolves stacks via `payload.dig('repository','full_name')` = `"victim-org/victim-repo"` [7](#0-6) , and calls `stack.sync_github` on the victim's stack — an action never authorized by `victim-org` [6](#0-5) .

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
