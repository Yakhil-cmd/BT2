## Title
Cross-organization webhook forgery enabling unauthorized commit status injection and stack sync/deploy triggers - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the HMAC signature against using an attacker-controlled field from the JSON body itself (`repository.owner.login` / `organization.login`), while the handlers that actually act on the payload (`StatusHandler`, `PushHandler`, `CheckSuiteHandler`) trust unrelated attacker-controlled fields (`sha`, `repository.full_name`) that are never cross-checked against the organization the signature was verified for. This breaks the binding: `organization authenticated == repository/commit written`. On a Shipit instance configured for multiple GitHub organizations (as documented and supported via `config/secrets*.yml`, each org with its own `webhook_secret`), anyone who legitimately controls a webhook-signing secret for *one* configured organization can forge events that mutate data belonging to a *different* configured organization/repository.

### Finding Description
`verify_signature` picks the `GitHubApp` (and thus the HMAC secret) to check against based on `repository_owner`, which is read straight from the untrusted JSON body: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

Once the signature check passes for that org, the *entire* raw JSON body (not just the org-scoping fields) is handed unmodified to the event handler: [2](#0-1) 

The handlers never re-verify that the object they mutate belongs to the organization that was authenticated:

- `Handler#stacks`/`#repository_name` resolves the target purely from `payload.dig('repository', 'full_name')`, a field independent from the `repository.owner.login` used for signature routing: [3](#0-2) 

- `StatusHandler` is the most severe case: it doesn't even scope by repository. It looks up *any* `Commit` in the entire Shipit instance matching an attacker-supplied `sha` and writes a status onto it: [4](#0-3) 

- `PushHandler` resolves stacks via `Repository.from_github_repo_name(repository_name)` where `repository_name` comes from `repository.full_name` and triggers `stack.sync_github(expected_head_sha: params.after)`: [5](#0-4) 

Because the multi-tenant configuration explicitly supports several independent GitHub organizations each with their own `webhook_secret` on a single Shipit deployment (see `config/secrets.development.shopify.yml` and `docs/setup.md`), a user who is only an owner/admin of *one* of those configured organizations — and thus legitimately knows/possesses that organization's GitHub App webhook secret — can compute a valid `X-Hub-Signature` for that organization while filling `repository.full_name` / `sha` / `organization.login` fields with values belonging to a completely different organization/repository tracked by the same Shipit instance. The signature check in `verify_signature` only proves "this body was signed by organization A's secret"; it does not prove "the repository/commit referenced inside this body belongs to organization A." [6](#0-5) 
`MembershipHandler` has the same structural issue for team membership, though `Team.find_or_create_by!(github_id:)` scoped by GitHub numeric team id somewhat limits collision, the `organization.login` used to tag the team is still taken from the unverified body content rather than the org that was cryptographically authenticated.

### Impact Explanation
This crosses the "unauthorized deploy" / "authorization escalation" bar explicitly listed as in-scope High impact:
- Via `StatusHandler`, an attacker who legitimately controls organization A's webhook secret can forge a `status` event with `sha` set to a real, publicly-visible commit SHA belonging to organization B's tracked repository (git SHAs are not secret), and `state: success` with the exact `context` Shipit's `deploy_spec` requires. This can satisfy the required-status gating used to determine whether a commit is deployable, contributing to an **unauthorized deploy** of organization B's stack that the attacker has no legitimate access to.
- Via `PushHandler`, the attacker can force `stack.sync_github` calls against organization B's stacks by supplying a crafted `repository.full_name`/`ref`/`after`, causing Shipit to resync/re-fetch and potentially fast-forward stack state based on attacker-chosen `expected_head_sha` for a repository the attacker does not own.
- Via `CheckSuiteHandler`, similarly, refresh-check-run jobs can be triggered against arbitrary stacks/commits outside the authenticated org.

This is not a denial-of-service or rate-limiting issue — it is a genuine authorization boundary bypass because the check that is supposed to gate "which org may write which data" (`verify_signature`) is decoupled from the data actually written.

### Likelihood Explanation
Exploitability requires the attacker to be a legitimate administrator of at least one GitHub organization/App that is configured in this shared Shipit instance's `config/secrets.yml` (i.e., know that org's `webhook_secret`, which they legitimately possess as the creator of their own org's GitHub App). This is the documented, supported multi-organization deployment model in this codebase (`docs/setup.md`, `config/secrets.development.shopify.yml` show multiple orgs configured side-by-side on one instance). No `ApiClient` token, GitHub App private key, or repository write access to the *victim* organization is required — only an organization slot on the shared instance, which several enterprises deliberately configure to consolidate CI/CD for many orgs behind one Shipit deployment. Given how directly the fields line up (attacker fully controls the JSON body except the outer HMAC, and the org used for HMAC selection is itself inside that body), this is straightforward to exploit for anyone in this position.

### Recommendation
Do not derive the HMAC-selection organization/repository purely from unauthenticated JSON body fields without binding it to the data the handler subsequently trusts. Concretely:
- After signature verification succeeds for organization X, constrain every handler's lookup (`Repository.from_github_repo_name`, `Commit.where(sha:)`, `Team`/`organization.login`) to only affect resources that belong to organization X (e.g., verify `Repository#owner` matches the verified `repository_owner`, and for `StatusHandler`, scope `Commit` lookup by joining through `Stack -> Repository` and asserting the repository's owner equals the authenticated organization).
- Reject events where `repository.owner.login` doesn't match the organization inferred from installation context (if using GitHub Apps, use the `installation.id`/target org from the verified installation rather than trusting body fields for routing).

### Proof of Concept
1. Configure Shipit with two organizations in `config/secrets.yml`, `org-attacker` (attacker owns/administers the GitHub App, knows its `webhook_secret`) and `org-victim` (has a tracked `Stack`/`Repository` with commit `SHA_VICTIM` that is pending a required status check named `ci/build`).
2. Attacker computes `X-Hub-Signature: sha1=HMAC(webhook_secret_of_org_attacker, body)` for the following forged body:
```json
{
  "sha": "SHA_VICTIM",
  "state": "success",
  "context": "ci/build",
  "repository": { "owner": { "login": "org-attacker" }, "full_name": "org-attacker/some-repo" }
}
```
3. POST this body with header `X-Github-Event: status` to `/webhooks`. `verify_signature` resolves `Shipit.github(organization: "org-attacker")`, verifies successfully using the attacker's own known secret.
4. `WebhooksController#create` dispatches to `StatusHandler`, which runs `Commit.where(sha: "SHA_VICTIM").each { |c| c.create_status_from_github!(params) }` — creating a passing `ci/build` status on `org-victim`'s commit, an organization the attacker has no legitimate relationship with, potentially unblocking that commit's deploy.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-43)
```ruby
        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```
