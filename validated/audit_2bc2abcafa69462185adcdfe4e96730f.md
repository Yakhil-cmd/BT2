Confirmed the key finding: `Handler#stacks` resolves the target repository via `payload.dig('repository', 'full_name')` [1](#0-0) , while `WebhooksController#verify_signature` selects which organization's `webhook_secret` to verify the HMAC against using a *different* field, `repository.owner.login` (or `organization.login`) [2](#0-1) . Both fields live in the same attacker-supplied JSON body, and neither is cross-checked against the other after signature verification.

### Title
Webhook signature verified against an organization selected from an unauthenticated payload field, while handlers act on a different unauthenticated payload field (`repository.full_name`) — cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` picks the GitHub App/organization (and therefore the `webhook_secret` used to validate `X-Hub-Signature`) using `repository_owner`, which is read straight out of the unauthenticated JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`) [3](#0-2) . Once the signature check passes, every event handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, all `PullRequest::*Handler`, etc.) determines the *actual* stack/repository to mutate using a completely different field from the same body: `payload.dig('repository', 'full_name')` [1](#0-0) . Because these two fields are never required to match, and because Shipit explicitly supports hosting multiple independent GitHub organizations/apps side by side with independent `webhook_secret`s [4](#0-3) , whoever legitimately controls delivery of real webhooks for **one** configured organization (Org A) can redirect the *content* of that signed delivery to act on any other configured organization/repository (Org B) simply by changing `repository.full_name` (and any other handler-trusted fields) while leaving `repository.owner.login`/`organization.login` set to Org A so the signature still checks out against Org A's secret.

### Finding Description
This mirrors the GitLab `MilestoneFinder` class of bug: a field that is trusted for a security decision (there, `params[:order]` used unsanitized in `reorder`; here, `repository_owner` used to pick the signing secret) is not the same field that is subsequently trusted for the actual state-changing operation (there, arbitrary SQL ordering; here, `repository.full_name` used to select the target `Stack`/`Repository` for sync, status updates, PR review-stack creation/archival, etc.).

Concretely:
1. `WebhooksController#verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` and verifies `X-Hub-Signature` against that organization's `webhook_secret` [5](#0-4) .
2. `repository_owner` is taken from the raw, unverified JSON body, not from any value guaranteed to match what gets acted upon later [3](#0-2) .
3. `WebhooksController#create` then dispatches the *entire* unmodified `params` hash to every registered handler for the event type [6](#0-5) .
4. All handlers (`Handler#stacks`) resolve their target `Repository`/`Stack` via `payload.dig('repository', 'full_name')`, a field independent from the one used in step 1 [1](#0-0) , and PR handlers similarly use `params.repository.full_name` directly [7](#0-6) .

Because nothing enforces `repository.owner.login == repository.full_name.split('/').first`, a party who legitimately holds delivery/signing capability for Organization A's webhook (i.e., is the real GitHub App/webhook sender for Org A, a normal and expected capability for anyone who can push to or receive events from a repo under Org A) can craft a JSON body where `organization.login`/`repository.owner.login` = `"orgA"` (so verification passes with Org A's known-valid signature) but `repository.full_name` = `"orgB/victim-repo"`, causing the handler to sync commits, flip commit statuses, or archive/unarchive/create review stacks for Org B's stack — an organization/repository the sender has no relationship to or credentials for.

### Impact Explanation
This breaks the binding "organization authenticated via signature == repository written to by the handler." A sender who is only entitled to act on Org A's repositories can trigger `GithubSyncJob`/`stack.sync_github` [8](#0-7) , fabricate/spoof commit statuses via `StatusHandler#process` (`commit.create_status_from_github!`) [9](#0-8) , or archive/unarchive/provision review stacks via the `PullRequest::*Handler` classes [10](#0-9)  for a repository under a different organization on the same shared Shipit instance. Spoofed CI statuses can influence `ci.require`/deployability checks that gate automated deploys, and forced re-sync/archival can disrupt or manipulate another team's deployment pipeline — this is a cross-repository/cross-organization write achieved without ever compromising Org B's own credentials.

### Likelihood Explanation
Exploitation only requires the attacker to be a legitimate webhook sender for *any one* organization hosted on the shared Shipit instance (multi-org hosting is a documented, supported configuration) [4](#0-3) ; no access to Org B's secrets, GitHub App, or Shipit session is needed. The only work required is crafting a JSON body whose `organization.login`/`repository.owner.login` differs from its `repository.full_name`, which the controller and handlers never cross-validate.

### Recommendation
Derive the organization used for signature verification from the same trusted repository identity that handlers act upon (e.g., verify against `repository.full_name`'s owner, or better, verify against every configured organization's secret and require the winning organization to equal the owner encoded in `repository.full_name`) before dispatching to handlers. Reject the request if `repository.owner.login`/`organization.login` does not match the owner segment of `repository.full_name`.

### Proof of Concept
1. Shipit is configured with two organizations, `orgA` and `orgB`, each with its own `webhook_secret`, hosting stacks for `orgA/app` and `orgB/app` respectively.
2. An attacker who is a legitimate contributor/webhook sender for `orgA` crafts a `push` event body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {"owner": {"login": "orgA"}, "full_name": "orgB/app"},
  "organization": {"login": "orgA"}
}
```
3. They sign it with `orgA`'s known/legitimate `webhook_secret` and set `X-Hub-Signature` accordingly.
4. `WebhooksController#verify_signature` resolves `repository_owner` to `"orgA"`, verifies successfully against `orgA`'s secret, and calls `PushHandler`.
5. `PushHandler#stacks` resolves the target via `repository.full_name` = `"orgB/app"`, and triggers `stack.sync_github` for `orgB`'s stack — a repository the attacker has no relationship with.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
