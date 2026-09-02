### Title
Webhook organization/repository binding mismatch allows cross-organization stack manipulation - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate an inbound webhook's HMAC signature against using `repository_owner`, which reads `repository.owner.login` (falling back to `organization.login`). The actual repository/stack that the webhook payload acts on, however, is resolved independently and later in `Handler#stacks`/`#repository_name`, which reads `repository.full_name`. Because these two payload fields are never checked against each other, a webhook cryptographically valid for one configured GitHub organization can be crafted to reference and mutate stacks belonging to a *different* configured organization on the same Shipit instance.

### Finding Description
`verify_signature` fetches the app credentials to check with: [1](#0-0) 
using [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up a distinct `GitHubApp` configuration (and thus a distinct `webhook_secret`) per organization — this multi-organization setup is exercised in the repo's own test fixtures (`test/dummy/config/secrets_double_github_app.yml`), confirming Shipit supports hosting several independently-configured GitHub organizations/apps on one instance.

Once signature verification passes, the handler dispatch resolves the *target* repository/stack independently, from a different key in the same JSON body: [3](#0-2) 
which is used by `Repository.from_github_repo_name` to look up the repository by `owner/name` and load its stacks: [4](#0-3) 

Handlers such as `PushHandler` then act directly on the resolved stacks: [5](#0-4) 

The binding that should hold is: **organization whose signature is verified == organization owning the repository the handler mutates**. Nothing in `WebhooksController` or `Handler` enforces `repository.owner.login == repository_owner used for signature verification`, nor that it matches `repository.full_name`'s owner segment. An attacker able to produce a validly-signed payload for *any one* configured organization (e.g., because they administer a repository/webhook in Organization A that is also onboarded to the shared Shipit instance) can set `repository.full_name` to `"OrgB/some-repo"` while keeping `repository.owner.login`/`organization.login` as `"OrgA"` so the signature check passes against OrgA's secret, yet the handler acts on OrgB's stacks.

### Impact Explanation
This crosses a cross-repository/cross-organization trust boundary: a party trusted only for Organization A's webhook traffic can trigger `GithubSyncJob` (via `push`), team/membership record creation, `check_suite` refreshes, or PR-driven review-stack provisioning for Organization B's stacks, none of which they should be able to reach. Depending on the handler this can force stack config resynchronization, review-stack provisioning, or trigger downstream deploy-eligibility state used elsewhere in Shipit, effectively an unauthorized cross-repository write into another tenant's stack state.

### Likelihood Explanation
This is only exploitable on Shipit instances that host multiple independently-configured GitHub organizations/apps (multi-tenant `github` config, as shown by `secrets_double_github_app.yml`), and requires the attacker to control a legitimate webhook secret/signing capability for at least one onboarded organization. This is a realistic operating mode for larger Shipit deployments serving several orgs, but not for the common single-org deployment where `repository_owner` for all repos is the same org.

### Recommendation
In `WebhooksController#verify_signature` and/or `Handler`, cross-validate that the organization used to select the webhook secret exactly matches the owner segment of `repository.full_name` used for repository/stack resolution, rejecting (422) any payload where these disagree, rather than trusting two independently-read fields from the same untrusted JSON body as if they were bound together.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. As an attacker with the ability to sign webhook deliveries for `OrgA` (e.g. because they control a webhook integration point for that org), submit a `push` event body where:
   - `repository.owner.login` = `"OrgA"` (or `organization.login = "OrgA"`), and
   - `repository.full_name` = `"OrgB/target-repo"`.
3. Compute `X-Hub-Signature` using `OrgA`'s `webhook_secret` over this exact body.
4. POST to `WebhooksController#create`; `verify_signature` passes because it only checks `repository_owner` ("OrgA") against `OrgA`'s secret.
5. `Handler#repository_name` reads `repository.full_name` = `"OrgB/target-repo"`, resolves `OrgB`'s stacks, and `PushHandler#process` calls `stack.sync_github` on them — a stack the attacker was never authorized to reach. [6](#0-5) [3](#0-2) [4](#0-3)

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
