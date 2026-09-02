### Title
Webhook signature is verified against `repository.owner.login`, but event handlers act on `repository.full_name`, allowing cross-organization writes - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
The GitHub webhook signature check authenticates *which organization's secret* signed the request by reading `repository.owner.login` from the JSON body, but every event handler afterwards resolves the target `Repository`/`Stack` using the unrelated `repository.full_name` field from the very same attacker-controlled body. Nothing ties the two fields together, so a party holding the webhook secret for *any* organization configured on the Shipit instance can forge a payload whose `owner.login` matches their own org (to pass signature verification) while `full_name` points at a different organization's repository, causing Shipit to process the event — and mutate that other organization's stacks — with no valid credential for it.

### Finding Description
`Shipit::WebhooksController#verify_signature` selects the `GitHubApp` (and therefore the HMAC secret) to validate against purely from the payload itself: [1](#0-0) [2](#0-1) 

`repository_owner` is `params.dig('repository', 'owner', 'login')`. `Shipit.github(organization: repository_owner)` looks up the per-organization webhook secret configured for that org (raising `GithubOrganizationUnknown` otherwise), i.e., the engine supports multiple independently-configured organizations, each with its own `webhook_secret`.

Once the signature check passes, `create` re-parses the same raw body and dispatches it to handlers: [3](#0-2) 

Every handler resolves the affected stacks with a *different* field from the same payload: [4](#0-3) 

`Repository.from_github_repo_name` then splits `full_name` on `/` and looks the repository up directly, independent of whichever organization's secret validated the request: [5](#0-4) 

The binding that should hold is:
`organization whose secret authenticated the request == owner of the repository the handler is about to mutate`

but the code only enforces:
`organization whose secret authenticated the request == payload["repository"]["owner"]["login"]` (a value inside the same forgeable body), while separately trusting `payload["repository"]["full_name"]` — a second, uncorrelated field — to pick the repository actually written to.

### Impact Explanation
This is a cross-repository/cross-tenant write. An attacker who legitimately administers a GitHub App installation for Organization A on a shared Shipit instance (and thus knows Organization A's `webhook_secret`, since they configured it themselves) can craft a payload with `repository.owner.login = "orgA"` (so the HMAC check passes with Org A's secret) and `repository.full_name = "orgB/private-repo"`. The dispatched handler will locate and act on Organization B's `Stack`/`Repository` even though the request was never signed with anything belonging to Organization B. Depending on event type this enables unauthorized mutations against another tenant's stacks (e.g., queuing `RefreshCheckRunsJob`, mutating pull-request/merge-queue state via the `pull_request` handlers, or affecting deploy/status tracking used to gate `continuous_deployment`) — i.e., a cross-repository write / potential unauthorized deploy trigger against a repository the attacker does not control, matching the "cross-repository writes" / "unauthorized deploy" Critical impact bucket.

### Likelihood Explanation
Requires only an unprivileged party who administers *any one* organization onboarded to the shared Shipit instance and can therefore see/know that organization's `webhook_secret` (a routine part of GitHub App setup they perform themselves). No GitHub App private key, `ApiClient` token, or repository write access to the victim organization is needed — only the ability to POST directly to the public `/webhooks` endpoint with a correctly computed HMAC for their own org, which is fully within reach of any org admin.

### Recommendation
In `Shipit::WebhooksController#verify_signature` (or in `Handler#repository_name`/`#stacks`), cross-check that the organization used to select the verifying secret (`repository.owner.login`) matches the owner segment of `repository.full_name` before dispatching to any handler, rejecting the request (422) on mismatch.

### Proof of Concept
1. Attacker administers the GitHub App installation for `orgA` on the shared Shipit instance and knows `orgA`'s configured `webhook_secret`.
2. Attacker crafts a JSON body for e.g. a `push`/`check_suite` event:
```json
{
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  },
  "...event-specific fields...": "..."
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(orgA_webhook_secret, body)>` and POSTs it to `/webhooks` with `X-Github-Event` set accordingly.
4. `verify_signature` resolves `repository_owner` = `"orgA"`, fetches `orgA`'s `GitHubApp`, and the signature validates successfully.
5. `WebhooksController#create` dispatches the parsed body to the matching handler(s); `Handler#stacks` resolves `Repository.from_github_repo_name("orgB/victim-repo")` and the handler mutates `orgB`'s stacks/tasks, even though the request was never authenticated for `orgB`.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
