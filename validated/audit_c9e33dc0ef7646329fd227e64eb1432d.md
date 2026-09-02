### Title
Webhook signature is verified against the payload's claimed organization while the write target is taken from an unrelated field, enabling cross-organization webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook against using `repository.owner.login` (or `organization.login`) taken from the untrusted JSON body, but the handler that actually acts on the payload resolves its write target from the independent `repository.full_name` field. Because nothing ties these two fields together, an attacker who legitimately possesses the webhook secret for one GitHub organization configured in Shipit can forge a signed payload that is verified as belonging to their own organization but that causes writes against a Stack belonging to a completely different, victim organization.

### Finding Description
`verify_signature` computes the signing identity purely from attacker-controlled JSON: [1](#0-0) [2](#0-1) 

It fetches the GitHub App config (and its `webhook_secret`) for that claimed organization and verifies the HMAC against it: [3](#0-2) 

Once the signature checks out, `Shipit::Webhooks.for_event(event)` dispatches the entire raw payload to the matching handler, e.g. `PushHandler`: [4](#0-3) 

But the base `Handler` resolves the actual write target from a *different* field of the same attacker-controlled payload — `repository.full_name` — with no cross-check against `repository.owner.login`: [5](#0-4) 

`PushHandler` then syncs whatever Stack belongs to that repository to an attacker-chosen SHA: [6](#0-5) 

`Repository.from_github_repo_name` simply splits `owner/name` out of the (independently controlled) `full_name` string and looks up any matching repository record, regardless of which organization's secret was used to authenticate the request: [7](#0-6) 

This is exactly the binding-mismatch pattern described in the report: the **organization that authenticated** the webhook (`repository.owner.login`, used only to pick the verification secret) is never equal to the **repository that is written** (`repository.full_name`, used to select the Stack that gets mutated). GitHub itself always sends consistent values for these two fields, but Shipit trusts a self-reported, unsigned-relationship between them rather than deriving both from a single verified source.

### Impact Explanation
Any organization/user that Shipit is configured to accept webhooks from (i.e., that has its own `webhook_secret` registered via `Shipit.github(organization:)`) can forge push/status/check_suite events that are cryptographically valid for their own org but target a Stack under a completely different organization. This crosses a repository/organization trust boundary the application intends to enforce (`GithubOrganizationUnknown`, per-org secrets) and can force unauthorized syncs (`stack.sync_github`) or spoofed CI status against a victim's stacks — a cross-repository write, matching the report's Critical impact bucket ("cross-repository writes" / "unauthorized deploy/rollback").

### Likelihood Explanation
Exploitability requires only possession of a webhook secret for *any one* organization that this Shipit instance already trusts — the normal, lower-privileged act of registering/configuring a webhook for the attacker's own organization/repo, not privileged access to the victim organization or to Shipit itself. In any multi-tenant Shipit deployment (the codebase explicitly supports per-organization GitHub App configs and raises `GithubOrganizationUnknown` for unrecognized orgs), this is directly reachable by an unprivileged external actor once they control one registered org's secret.

### Recommendation
Verify the signature against the secret for the same organization/repository the payload will actually be applied to, and reject payloads where `repository.owner.login` does not match the owner segment of `repository.full_name` (or derive both from a single canonical field). Alternatively, resolve the target Stack/Repository using the same `repository_owner` value that was used for signature verification, rather than trusting the independently-supplied `full_name`.

### Proof of Concept
1. Attacker registers/administers a webhook for `attacker-org` in a Shipit instance that supports multiple organizations, obtaining its `webhook_secret` (`S_A`).
2. Attacker sends:
```
POST /github/webhooks
X-Github-Event: push
X-Hub-Signature: sha1=HMAC-SHA1(S_A, body)

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "attacker-org" }
  }
}
```
3. `verify_signature` computes `repository_owner = "attacker-org"`, fetches `attacker-org`'s config, and the signature verifies successfully because it was computed with `S_A`.
4. `PushHandler#repository_name` reads `"victim-org/victim-repo"` from the same payload, looks up the victim's `Repository`/`Stack`, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` — a write to a stack the attacker has no GitHub-side access to, despite having authenticated only as `attacker-org`.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
