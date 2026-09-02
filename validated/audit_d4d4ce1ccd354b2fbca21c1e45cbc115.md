### Title
Webhook signature is verified against `repository.owner.login`, but the repository actually written to is derived from the unverified `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` (or `organization.login`) of the *raw, attacker-supplied* JSON body itself. [1](#0-0) [2](#0-1)  Once the signature check passes, the same raw payload is handed unmodified to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`, and every handler resolves the target repository/stack from a *different* field of the same payload: `Handler#repository_name` reads `payload.dig('repository', 'full_name')`, which is then looked up via `Repository.from_github_repo_name` to find the `Stack`(s) that get acted on. [3](#0-2) [4](#0-3) 

Because the signature check and the repository-resolution step read two independently-controlled JSON keys (`repository.owner.login` vs `repository.full_name`) from the same untrusted body, nothing forces them to refer to the same repository/organization. A party who can produce a validly-signed webhook for organization A (e.g. a legitimate integrator/admin of an org that Shipit tracks) can set `repository.owner.login` to `"orgA"` (so the signature validates against orgA's `webhook_secret`) while setting `repository.full_name` to `"orgB/some-other-repo"`. `PushHandler`, `StatusHandler`, and `CheckSuiteHandler` will then act on `orgB`'s stacks/commits, even though the request was only authenticated as belonging to `orgA`. [5](#0-4) [6](#0-5) 

### Finding Description
The binding that should hold is: *organization whose secret authenticated the request* == *organization/repository the handler mutates state for*. Instead:

- `verify_signature` picks the `GitHubApp`/secret via `repository_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. [2](#0-1) 
- `Handler#stacks` / `Handler#repository_name` independently reads `payload.dig('repository', 'full_name')` to look up the `Repository` and its `Stack`s. [3](#0-2) 
- `Repository.from_github_repo_name` splits this attacker-controlled string on `/` and does a straight `find_by(owner:, name:)` with no cross-check against `repository_owner`. [4](#0-3) 
- `StatusHandler#process` is even weaker: it does not scope by repository at all, matching purely on a global `Commit.where(sha: params.sha)`. [6](#0-5) 

Since HMAC verification (`verify_webhook_signature`) only proves "this body was signed with orgA's secret," not "this body concerns an orgA repository," an attacker who legitimately controls orgA's webhook secret (e.g. is a GitHub org owner who configured the Shipit webhook for their own, unrelated organization) can forge JSON bodies that pass the `X-Hub-Signature` check for orgA yet target any other organization/repository Shipit tracks, by simply diverging `repository.owner.login` from `repository.full_name`.

### Impact Explanation
This does not, by itself, achieve RCE or `GITHUB_TOKEN` exfiltration, but it does break a deployment-trust binding across organizations: a party authorized only for org A's webhook can drive `GithubSyncJob` for an org B stack (forcing resyncs / making the sync job hit org B's real GitHub API using the app's own credentials for org B), or push forged `commit_status` records (`state`, `target_url`, `description`, `context`) onto commits belonging to stacks under a completely different, unauthenticated-for organization, since `StatusHandler` matches by SHA globally without any repository/org check. [6](#0-5)  Forged/incorrect commit-status entries can influence deploy safety checks that gate deploys on commit status. This is a cross-organization write of state that the signing organization was never authorized to write, matching the "organization that authenticated versus the repository that is written" trust-binding category.

### Likelihood Explanation
Exploitation requires the attacker to already control a valid `webhook_secret` for at least one organization configured in the Shipit instance (i.e., they are a legitimate webhook-signing party for org A but not org B). This is a real-world multi-tenant scenario for any Shipit deployment that tracks stacks across more than one GitHub organization/app config, since nothing in `WebhooksController` or `Handler` cross-validates the two payload fields against each other.

### Recommendation
After signature verification, re-derive the repository/organization strictly from the same field that was cryptographically bound to the verified organization (or verify that `repository.full_name`'s owner segment matches `repository_owner` used for signature selection) before dispatching to handlers. Additionally, `StatusHandler` should scope `Commit` lookups to commits belonging to stacks whose repository matches the verified `repository_owner`/`full_name`, not a bare global `Commit.where(sha:)`.

### Proof of Concept
1. Configure two GitHub organizations, `orgA` and `orgB`, each with a distinct `webhook_secret` in Shipit's config, both with stacks in Shipit.
2. As a party with legitimate access to `orgA`'s webhook secret, construct a `status` (or `push`) webhook JSON body where:
   - `repository.owner.login = "orgA"`
   - `repository.full_name = "orgB/victim-repo"`
   - `sha` set to a known commit SHA of a commit tracked by an `orgB` stack, `state = "success"`.
3. Sign the raw body with `orgA`'s `webhook_secret` via HMAC-SHA1 and send it as `X-Hub-Signature` to `POST /webhooks`.
4. `verify_signature` resolves `Shipit.github(organization: "orgA")` and successfully verifies the signature. [1](#0-0) 
5. `StatusHandler#process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` and creates a forged success status on the `orgB` commit, despite the request only ever being authenticated for `orgA`. [6](#0-5)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
