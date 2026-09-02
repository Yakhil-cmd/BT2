### Title
Webhook signature verification binds the wrong field — organization authenticated (`repository.owner.login`) is never checked against the repository actually written (`repository.full_name`), enabling cross-repository/cross-organization webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/HMAC secret to validate a webhook against using `repository.owner.login` (falling back to `organization.login`), but every event handler resolves the repository/stack to actually act on using a completely different field of the same payload: `repository.full_name`. Nothing cross-checks that these two values agree.

### Finding Description
`verify_signature` computes: [1](#0-0) 
using [2](#0-1) 
i.e. `Shipit.github(organization: repository_owner)` picks a per-organization `GitHubApp` (and its `webhook_secret`) keyed off `repository.owner.login` / `organization.login`, as configured in `lib/shipit.rb`'s multi-org lookup: [3](#0-2) 

Once the HMAC passes, `create` dispatches the raw parsed body to handlers: [4](#0-3) 

Every handler resolves the target repository using `repository.full_name`, not `repository.owner.login`: [5](#0-4) 

`PushHandler` then triggers a sync against whatever stack matches that repository/branch, using an attacker-supplied `after` SHA: [6](#0-5) 

Other handlers (`OpenedHandler`, `ReopenedHandler`, `EditedHandler`, `LabelCapturingHandler`, etc.) all resolve `repository` the same way via `Shipit::Repository.from_github_repo_name(params.repository.full_name)`: [7](#0-6) 

Because the HMAC covers the *entire* raw request body, an attacker cannot alter a payload after computing its signature — but this doesn't matter, because they can construct and sign the payload themselves from scratch. In a documented multi-organization deployment (`docs/setup.md` §"Using Multiple Github Applications"), each onboarded GitHub organization has its own `webhook_secret`. An org administrator who legitimately owns/administers *their own* GitHub App installation on Org A (and therefore knows Org A's own `webhook_secret`, obtained entirely through documented, legitimate setup) can:

1. Build a JSON payload with `repository.owner.login = "org-a"` (so `verify_signature` picks Org A's `GitHubApp` and secret) and `organization.login` likewise, but set `repository.full_name = "org-b/victim-repo"` — an entirely different, unrelated organization/repository hosted on the same Shipit instance.
2. HMAC-sign the whole payload with Org A's own known secret.
3. POST it to `/webhooks`. `verify_signature` succeeds because it only checks the signature against Org A's secret, which is valid for the payload as a whole (the attacker is fully in control of that payload).
4. Handlers act on `org-b/victim-repo`, e.g. `PushHandler` finds Org B's real `Stack` and calls `stack.sync_github(expected_head_sha: params.after)` with an attacker-chosen SHA, or `PullRequest::OpenedHandler` provisions a review stack, or the `membership`/`status`/`check_suite` handlers similarly touch state scoped to Org B — despite the attacker never having any credential, secret, or authorization tied to Org B.

The root cause is a broken equality: `organization authenticated (repository.owner.login used to pick the HMAC secret) == repository written (repository.full_name used by every handler to locate the Repository/Stack)`. Nothing in `WebhooksController` or `Handler` enforces that these two fields refer to the same repository.

### Impact Explanation
This breaks the cross-repository/cross-organization isolation that the entire multi-org webhook design (`Shipit.github(organization:)`, per-org `webhook_secret`) is meant to provide. An attacker who is a legitimate, unprivileged (with respect to the target org) GitHub App owner on any one onboarded organization can forge webhook events for **any other repository/stack hosted on the same Shipit instance**, driving Shipit-side state changes (triggering `GithubSyncJob` with an attacker-chosen `expected_head_sha`, auto-provisioning/unarchiving review stacks, capturing arbitrary pull-request labels, creating arbitrary teams/users via the `membership` handler) without ever possessing Org B's webhook secret, API token, or repository access. This is a cross-repository write achieved purely by exploiting a validation/action field mismatch — matching the Critical "cross-repository writes" impact bucket.

### Likelihood Explanation
Likelihood is high in any Shipit deployment that follows the documented multi-organization configuration (explicitly supported and documented in `docs/setup.md`). Any org that has legitimately onboarded its own GitHub App — a normal, unprivileged, self-service action from Shipit's perspective — obtains everything needed to mount this attack against every other org/repository on the same instance. No GitHub-side compromise, no Shipit account, and no target-org secret is required.

### Recommendation
In `WebhooksController#verify_signature` / `Handler`, cross-check that the organization used to select the verifying `GitHubApp` (`repository.owner.login` / `organization.login`) matches the owner embedded in `repository.full_name` before dispatching to handlers, and reject the request (422) on mismatch. More robustly, derive the repository used to select the webhook secret and the repository acted upon from the *same* single field, rather than two independently-trusted fields of the payload.

### Proof of Concept
Note: this PoC is derived purely from static analysis of `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`, and `app/models/shipit/webhooks/handlers/push_handler.rb`; it has not been executed against a running instance.

```ruby
require 'openssl'
require 'net/http'
require 'json'

# Attacker legitimately administers Org A's GitHub App and knows its webhook_secret
org_a_secret = "org-a-known-secret"

payload = {
  "ref"   => "refs/heads/master",
  "after" => "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", # attacker-chosen SHA
  "repository" => {
    "owner" => { "login" => "org-a" },       # used ONLY for signature org lookup
    "full_name" => "org-b/victim-repo"       # used by handlers to pick the real Stack
  },
  "organization" => { "login" => "org-a" }
}.to_json

signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", org_a_secret, payload)

uri = URI("https://shipit.example.com/webhooks")
req = Net::HTTP::Post.new(uri, {
  "Content-Type"    => "application/json",
  "X-Github-Event"  => "push",
  "X-Hub-Signature" => signature
})
req.body = payload

# verify_signature succeeds (valid HMAC for org-a's secret over the whole payload),
# but PushHandler resolves and syncs Org B's "victim-repo" stack using the
# attacker-controlled `after` SHA, without any credential belonging to Org B.
Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) { |http| http.request(req) }
```

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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
