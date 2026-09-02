### Title
Webhook signature is verified against the payload's `repository.owner.login`/`organization.login` while event handlers act on the independent `repository.full_name` field, allowing a webhook signed by one configured GitHub organization's secret to write to a stack belonging to any other repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against by reading `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`). [1](#0-0) [2](#0-1) 

However, the actual event handlers that mutate state (`PushHandler`, `StatusHandler`, etc.) resolve the target `Stack`/`Commit` using an entirely different, independently-controlled JSON field: `payload.dig('repository', 'full_name')`. [3](#0-2) 

Nothing enforces that `repository.owner.login` (the field the signature is checked against) matches the owner segment embedded in `repository.full_name` (the field the handler uses to look up and mutate the `Repository`/`Stack`). `Repository.from_github_repo_name` blindly splits `full_name` on `/` and looks the row up by owner/name. [4](#0-3) 

### Finding Description
This is a direct analog of the CVE-2023-33964 bug class: a field that is *acted upon* (here, `repository.full_name`, used to select the Stack/Commit that gets written to) is never covered by the verification step (here, HMAC signature verification, which is scoped only to `repository.owner.login`/`organization.login`). The equality that should hold but is not enforced is:

`organization whose webhook_secret authenticated the request == owner segment of the repository that the handler mutates`

Shipit explicitly supports hosting multiple GitHub organizations in one instance, each with its own `webhook_secret`, keyed by organization login (`Shipit.github(organization: ...)`), as documented in the "Using Multiple Github Applications" section. [5](#0-4) 

Because `WebhooksController#create` passes the raw parsed JSON straight to the handlers after only checking the signature scoped to `repository_owner` (or `organization.login`), an attacker who legitimately controls their own GitHub organization/App installation registered with this Shipit instance ("OrgA") knows OrgA's `webhook_secret` (they configured/installed it). They can POST directly to `/webhooks` (no GitHub relay required) with:
- `repository.owner.login = "OrgA"` / `organization.login = "OrgA"` (satisfies `verify_signature`, computed against OrgA's `webhook_secret`)
- `repository.full_name = "OrgB/victim-repo"` (used by `PushHandler`/`StatusHandler` to locate and mutate `OrgB`'s `Stack`/`Commit`)

`verify_signature` will pass because the HMAC is computed correctly for OrgA using OrgA's own secret; it never covers or cross-checks `full_name`. `Handler#stacks` then resolves the `Repository` from `full_name`, i.e., `OrgB/victim-repo`, entirely disconnected from the org that authenticated the request. [6](#0-5) [7](#0-6) 

### Impact Explanation
This breaks the boundary "an organization that authenticated versus the repository that is written," matching the required High-severity criteria. Concretely, an attacker who controls a single low-privilege organization/App installation on a shared multi-org Shipit instance can:
- Trigger `sync_github` on any other organization's `Stack` via `PushHandler`, forcing unwanted sync operations against a stack it does not own.
- Inject fabricated commit statuses on any other organization's commits via `StatusHandler#process` → `Commit#create_status_from_github!`, which can affect deployability/merge-queue gating decisions on repositories the attacker has no legitimate access to.

This constitutes a cross-repository write performed via a credential (webhook_secret) that is scoped to a different repository/organization than the one being mutated - exactly the kind of unauthorized cross-tenant write the rules identify as Critical/High impact.

### Likelihood Explanation
Likelihood is high wherever an operator hosts multiple organizations on one Shipit deployment (an explicitly documented and supported configuration). Any organization admin/installer of a GitHub App on that instance — an otherwise unprivileged actor with respect to other tenants' repositories — can exploit this without needing GitHub relay, a Shipit session, or any `ApiClient` token; they only need the `webhook_secret` for their own org, which they legitimately possess, and the ability to send an arbitrary HTTP POST to `/webhooks`.

### Recommendation
In `Handler#stacks`/`Handler#repository_name` (or centrally in `WebhooksController`), enforce that the owner segment of `repository.full_name` matches the verified `repository_owner`/`organization.login` used in `verify_signature`, rejecting the payload (e.g., `head(422)`) on mismatch before dispatching to any handler.

### Proof of Concept
1. Attacker legitimately installs/administers a GitHub App for organization `attacker-org` on the shared Shipit instance, and knows `attacker-org`'s configured `webhook_secret`.
2. Attacker crafts a JSON payload for the `push` event:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org webhook_secret, raw_body)>` and sends it as `X-Github-Event: push` to `POST /webhooks`.
4. `verify_signature` resolves `repository_owner = "attacker-org"`, fetches `attacker-org`'s `webhook_secret`, and the signature matches → request proceeds.
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")`, and calls `stack.sync_github(expected_head_sha: "deadbeef")` on the victim organization's stack — an action performed on a repository the attacker's authenticated credential was never scoped to.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
