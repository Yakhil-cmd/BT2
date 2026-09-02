### Title
Cross-organization commit-status forgery bypasses per-org webhook signature binding, enabling unauthorized CI-check satisfaction - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`SubAccounts::setAssetAllowances()`-style "no scoping check on the acted-upon target" bug class maps directly onto Shipit's webhook pipeline: the signature verification step authenticates a webhook against the *organization* derived from the payload, but the `status` event handler that acts on the data never re-checks that the commit being updated actually belongs to that same organization/repository. This breaks the binding: `organization that authenticated == repository/commit that is written`.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to validate the request signature against based on the attacker-influenced payload field `repository.owner.login` (falling back to `organization.login`): [1](#0-0) [2](#0-1) 

This only proves the payload was legitimately signed *by the GitHub App installation of one particular organization* configured in `secrets.yml` (Shipit supports multiple organizations, each with its own `webhook_secret`, per `config/secrets.development.example.yml` and `docs/setup.md`). It says nothing about which specific repository or commit the payload's *content* references.

Once the signature check passes, `WebhooksController#create` dispatches the entire raw JSON body, unmodified, to every registered handler for the event type: [3](#0-2) 

For the `status` event, `Shipit::Webhooks::Handlers::StatusHandler#process` looks up affected commits **globally by SHA only**, with no repository/organization scoping at all: [4](#0-3) 

Compare this to `PushHandler`, which does scope through `Handler#stacks`/`#repository_name`, which reads `payload.dig('repository', 'full_name')`: [5](#0-4) 

but `StatusHandler` bypasses that entirely and just does `Commit.where(sha: params.sha)`, meaning a commit SHA that happens to also exist (or be created) under a completely different repository/stack (belonging to a different, unrelated GitHub organization also onboarded to the same Shipit instance) will be updated.

**The trust binding broken:** the equality that should hold is:
```
organization whose webhook_secret verified the signature == organization/repository whose commit status is mutated
```
Because `verify_signature` derives the org from `repository.owner.login`/`organization.login`, while `StatusHandler` derives the target purely from `sha` (a value fully controlled by the attacker's own signed payload, and which they can set to any 40-hex-character string, including the SHA of a public commit in a completely different tracked stack), an attacker who legitimately controls a repository/webhook delivery for **their own** onboarded organization (Org B) can forge a `status` webhook, correctly signed with Org B's `webhook_secret`, whose `sha` field names a commit belonging to Org A's stack. `StatusHandler` will happily attach an arbitrary CI status (e.g. `state: "success"`, forged `context`) to Org A's commit.

### Impact Explanation
Commit statuses gate Shipit's CI-readiness/merge-queue logic (`ci.require` in `shipit.yml`, `Shipit::Status`/`Status::Group`, `MergeRequest`). By forging a "success" status on an arbitrary commit SHA belonging to a stack the attacker has no legitimate access to, an attacker can satisfy Shipit's CI requirement checks for that commit, which can unblock deploys and/or the merge queue for a stack/repository the attacker does not control — an unauthorized deploy/merge, matching the report's "Critical" impact bar. This requires only that the attacker's own org/repo is also configured in the same multi-tenant Shipit instance (a legitimate, low-privilege position, not requiring any Shipit session, `ApiClient` token, or the target org's secret) — no privileged credential for the *victim* organization is needed.

### Likelihood Explanation
Exploitability requires: (1) the Shipit instance is configured for more than one GitHub organization (explicitly supported/documented as a standard configuration in `secrets.development.example.yml`/`docs/setup.md`), and (2) the attacker knows a target commit SHA in another onboarded org's tracked stack (commit SHAs are visible in public repos, PR pages, or Shipit's own commit history views, so this is not a meaningful barrier). Given that, forging a correctly-signed webhook from a self-controlled/self-owned repository is well within the reach of anyone with push access or a GitHub App/webhook of their own that is subscribed under Org B. This is a realistic, low-effort attack path in any multi-org Shipit deployment.

### Recommendation
`StatusHandler` (and any other handler that doesn't route through `Handler#stacks`) must scope commit/status lookups to the repository named in the same payload used for signature verification, e.g. `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { owner: repository_owner, name: repo_name })`, and the webhooks controller should pass along a verified `repository_owner`/`full_name` context that handlers are required to check against, rather than trusting the raw, re-parsed JSON body uniformly for both authentication and mutation. More generally, enforce that the organization used to verify the signature is the same organization value used by every handler when resolving the affected record.

### Proof of Concept
1. Configure Shipit (per `docs/setup.md`) with two organizations, `orgA` and `orgB`, each with a distinct GitHub App/`webhook_secret`, both with stacks tracked in Shipit.
2. As a user with push/admin access only to a repo under `orgB` (attacker's own org), trigger (or directly forge, since you legitimately hold `orgB`'s `webhook_secret` via your own GitHub App installation permissions, or simply cause GitHub to deliver) a `status` webhook event whose JSON body is:
   ```json
   {
     "sha": "<sha_of_a_commit_in_orgA/some-repo>",
     "state": "success",
     "context": "ci/required-check",
     "repository": { "owner": { "login": "orgB" }, "full_name": "orgB/attacker-repo" }
   }
   ```
   signed with `orgB`'s webhook secret.
3. `WebhooksController#verify_signature` resolves `repository_owner` to `"orgB"`, fetches `orgB`'s `github_app`, and the signature validates successfully (since it was genuinely computed with `orgB`'s secret).
4. `StatusHandler#process` executes `Commit.where(sha: params.sha)`, finds the commit belonging to `orgA`'s stack (no ownership check performed), and calls `commit.create_status_from_github!(params)`, writing a forged `"success"` status for `ci/required-check` onto `orgA`'s commit.
5. If `orgA`'s `shipit.yml` has `ci.require: ["ci/required-check"]`, this forged status can now satisfy the CI gate and unblock an unauthorized deploy/merge of that commit in `orgA`'s stack, entirely without any credential belonging to `orgA`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
