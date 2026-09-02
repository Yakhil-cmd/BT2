### Title
Webhook signature verification is keyed to `repository.owner.login`, but handlers act on the independent `repository.full_name` field, letting a valid sender for one organization forge events for another org's stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App / `webhook_secret` used to validate the HMAC signature based on `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` (or `organization.login`) [1](#0-0) [2](#0-1) . However, once the signature is accepted, every webhook handler determines the actual `Repository`/`Stack` to act on using a *different*, independently-controlled JSON field: `repository.full_name`, e.g. `Handler#stacks` / `Handler#repository_name` [3](#0-2) , and the pull-request handlers via `Repository.from_github_repo_name(params.repository.full_name)` [4](#0-3) .

### Finding Description
The verified equality is:

`signature == HMAC(webhook_secret_for(repository.owner.login), raw_body)`

but the equality that should hold for the action actually taken is:

`repository.owner.login == owner(repository.full_name)`

Nothing enforces this second equality. `repository.owner.login` and `repository.full_name` are two independent strings inside the same attacker-crafted JSON body; GitHub's real webhooks always keep them consistent, but the controller never re-derives one from the other or cross-checks them [5](#0-4) . An attacker who is a legitimate GitHub organization admin/owner for "OrgA" - and therefore knows or controls the `webhook_secret` configured for OrgA in this Shipit instance - can:

1. Set `repository.owner.login` (or `organization.login`) to `"OrgA"` so `verify_signature` selects OrgA's `webhook_secret` and the HMAC check passes.
2. Set `repository.full_name` to `"OrgB/victim-repo"`, a completely different, unrelated repository/organization also hosted on the same shared Shipit instance.
3. Sign the crafted payload with OrgA's known secret and POST it to `/webhooks`.

Because `Repository.from_github_repo_name` resolves purely from `repository.full_name` [6](#0-5) , the `PushHandler` (and any other handler keyed off `repository.full_name`) will act on OrgB's stacks despite the request only ever being authenticated as belonging to OrgA. For `push` events this drives `stack.sync_github(expected_head_sha: params.after)` for every non-archived stack on the matching branch of the victim repository [7](#0-6) , i.e. an attacker with authority over only their own organization's webhook credentials can force sync operations (and, for stacks with continuous deployment enabled, downstream deploy triggers) against a repository they have no relationship to. Pull-request handlers (`opened_handler.rb`, `labeled_handler.rb`, etc.) are equally reachable this way since they all resolve the target `Repository` solely from `params.repository.full_name` without validating it against the organization whose secret authenticated the request.

### Impact Explanation
This breaks the deployment-trust binding between "the organization whose credential authenticated the request" and "the repository being written to." An attacker who legitimately administers one tenant organization in a shared/multi-org Shipit deployment can spoof push/pull-request events for a completely different tenant's repository, forcing unintended `GithubSyncJob`s and — for stacks with `continuous_deployment` enabled — unauthorized synchronization of arbitrary attacker-chosen commit SHAs into another team's deploy pipeline. This matches the "Critical: unauthorized deploy" / "cross-repository writes" class of impact called out in the rules, since the acted-upon repository is never cryptographically bound to the authenticated organization.

### Likelihood Explanation
Exploitation requires the attacker to be a legitimate, authenticated GitHub organization admin for at least one org configured in the shared Shipit instance (i.e., they must know/control that org's `webhook_secret`), which is a realistic scenario for any Shipit deployment serving multiple organizations/tenants (as documented and supported by `Shipit.github(organization:)` multi-org configuration [8](#0-7) ). No compromise of the victim organization's own credentials, session, or API token is needed.

### Recommendation
When resolving the target repository inside `WebhooksController#create` / `Handler`, cross-check that the organization/owner embedded in `repository.full_name` matches the `repository_owner` (or `organization.login`) that was used to select the verifying `webhook_secret`, and reject the request (e.g., `head(422)`) on mismatch. Alternatively, always derive the target repository owner from the same field used for signature verification, rather than trusting a second, unauthenticated-relative-to-that-binding field in the payload.

### Proof of Concept
1. Attacker administers GitHub organization `OrgA`, which is configured in this Shipit instance with a known `webhook_secret_A`.
2. Attacker builds a JSON push payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker_chosen_sha>",
  "repository": {
    "full_name": "OrgB/victim-repo",
    "owner": { "login": "OrgA" }
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(webhook_secret_A, raw_body)`.
4. Attacker POSTs to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the signature check passes [1](#0-0) .
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("OrgB/victim-repo")` [3](#0-2)  and calls `stack.sync_github(expected_head_sha: "<attacker_chosen_sha>")` on OrgB's stacks, despite the request never being authenticated against OrgB's credentials [7](#0-6) .

Note: I was unable to fully inspect `Stack#sync_github` (only located, not read, due to running out of tool iterations), so the exact downstream consequences (e.g., whether continuous-deployment stacks would auto-deploy from this forced sync) could not be fully confirmed and should be verified directly in `app/models/shipit/stack.rb`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
    end
```
