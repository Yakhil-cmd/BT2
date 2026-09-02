### Title
Webhook status/push events authenticate against `repository.owner.login`'s GitHub App but act on an unrelated repository/commit named elsewhere in the payload - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App (and thus which `webhook_secret`) to verify a webhook against using `repository.owner.login` (falling back to `organization.login`) from the JSON body. Once that signature check passes, the individual webhook handlers act on a *different* field of the same body to decide what to mutate: `Handler#repository_name` reads `payload.dig('repository', 'full_name')`, and `StatusHandler#process` doesn't even use the repository at all — it looks up commits globally by `sha`. Nothing ties the organization whose secret validated the request to the repository/commit that ends up being modified, so a webhook correctly signed for tenant/org A can create/modify CI status, sync jobs or review-stack state for a repository belonging to tenant/org B.

### Finding Description
`verify_signature` derives the authenticating organization purely from attacker-controlled JSON fields and fetches that org's `GitHubApp`: [1](#0-0) [2](#0-1) 

The signature is verified with that org's own secret: [3](#0-2) 

Note `return true unless webhook_secret` — per-org webhook secrets are documented as optional (`docs/setup.md`), so any org onboarded without one accepts *any* signature (or none) for a payload claiming to be from it.

Downstream, `Handler#repository_name` derives the target repository from a *different, independent* JSON field (`repository.full_name`), with no cross-check against `repository.owner.login`/`organization.login` used for authentication: [4](#0-3) 

`PushHandler` then syncs whatever stacks belong to that (attacker-supplied) `full_name`: [5](#0-4) 

Most severe is `StatusHandler`, which doesn't scope by repository at all — it updates the CI status of any commit in the entire Shipit install by SHA: [6](#0-5) 

`Repository.from_github_repo_name` / `github_app` show that repository ownership and GitHub-App/org association are supposed to be tightly coupled per-repository, but the webhook layer never enforces that the authenticating org matches the repository being mutated: [7](#0-6) [8](#0-7) 

**Binding that should hold but doesn't:**
`organization whose GitHub App secret authenticated the request` == `organization/repository owning the commit or stack the request mutates`.

Before the PR/request: this equality is implicit because in a normal, single-tenant Shipit deployment (or a real GitHub-originated webhook) the fields always agree.
After a crafted raw POST to `/webhooks`: an attacker who legitimately controls (or whose org has no `webhook_secret` configured for) org A can sign a payload whose `repository.owner.login`/`organization.login` is A (or an org with a blank secret) while `repository.full_name` / commit `sha` refers to a completely unrelated stack under org B. The equality breaks, and Shipit acts on B's data using A's authentication.

### Impact Explanation
Using `StatusHandler`, an attacker who can produce a validly-signed webhook for any onboarded organization (including one intentionally left without a `webhook_secret`, per the documented "optional" setting) can inject an arbitrary CI status (e.g. `state: "success"`, matching the `context` Shipit is configured to `require`) for any commit SHA on any stack in the Shipit instance, regardless of which repository/organization that commit actually belongs to. Since required/blocking statuses gate continuous deployment (`app/models/shipit/deploy_spec.rb` `required_statuses`, and the commit checks that use them), this can be used to force a stack that the attacker has no legitimate access to into an "eligible to deploy" state, resulting in an unauthorized deploy — a Critical-tier impact per the program's rules. `PushHandler`/pull-request handlers extend the same primitive to trigger sync jobs or review-stack provisioning/archival for arbitrary repositories named only by `full_name`, independent of the org that authenticated the request.

### Likelihood Explanation
Exploitability depends on the operator running the documented multi-tenant configuration (`docs/setup.md`, "Using Multiple Github Applications") where several GitHub orgs share one Shipit instance, each with its own optional `webhook_secret`. Any org configured without a secret (explicitly supported by the code and docs) turns `verify_webhook_signature` into a no-op for that org, letting an unauthenticated remote attacker forge the initial trust step; from there the missing binding between authenticating org and mutated repository/commit is unconditional application logic, not a configuration issue.

### Recommendation
- In each webhook handler, resolve the repository from `repository.full_name` and require that its `owner` matches the organization that was used to select the `GitHubApp`/verify the signature (`repository_owner` from the controller) before processing.
- In `StatusHandler`, scope the `Commit.where(sha: params.sha)` lookup to commits whose stack's repository matches the authenticated organization/repository from the payload, instead of matching by SHA alone across the whole instance.
- Do not silently accept unsigned/unverifiable webhooks (`return true unless webhook_secret` in `lib/shipit/github_app.rb`) — require a configured secret for every registered organization, or fail closed.

### Proof of Concept
1. Shipit is configured with two GitHub orgs (per `docs/setup.md` multi-app setup): `org-a` (has no `webhook_secret` set, which is documented as optional) and `victim-org` (owns a stack tracked by Shipit with a `shipit.yml` `ci.require` context of `ci/checks`).
2. Attacker (no privileges on `victim-org`) sends:
```
POST /webhooks
X-Github-Event: status
Content-Type: application/json

{
  "repository": {"owner": {"login": "org-a"}, "full_name": "org-a/whatever"},
  "sha": "<sha of the commit currently pending on the victim stack>",
  "state": "success",
  "context": "ci/checks"
}
```
3. `verify_signature` calls `Shipit.github(organization: 'org-a')`; because `org-a` has no configured `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb` line 77).
4. `StatusHandler#process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, matching the commit that actually belongs to `victim-org`'s stack and marking `ci/checks` as passing, satisfying `deploy_spec.required_statuses` for a repository the attacker never authenticated against.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-23)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/repository.rb (L98-102)
```ruby
    protected

    def github_app
      Shipit.github(organization: owner)
    end
```
