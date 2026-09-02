### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but event handlers act on the unrelated `repository.full_name` field, letting one organization's webhook secret forge events for a different organization's stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
This is the same "clear/act on the wrong record" class of bug as the `MarginDex` report: a value is trusted to authenticate an actor, but a *different*, independently-controlled field of the same payload is what's actually acted upon downstream. In Shipit, the webhook controller selects which organization's secret to verify the HMAC signature against using `repository.owner.login` (or `organization.login`), while every event `Handler` resolves the target `Stack`/`Repository` using the completely separate `repository.full_name` field. Nothing binds these two fields together.

### Finding Description
`WebhooksController#verify_signature` picks the `GitHubApp` (and therefore the `webhook_secret`) to validate against using an attacker-controlled, not-yet-verified JSON field: [1](#0-0) [2](#0-1) 

Once the signature check "passes" (because it was computed with the secret belonging to `repository.owner.login`), the raw payload is handed unchanged to all registered handlers: [3](#0-2) 

Every handler, however, determines *which repository/stack to act on* from a different field entirely - `repository.full_name` - via the base `Handler` class: [4](#0-3) 

`Repository.from_github_repo_name` looks up the target purely by that `owner/name` pair parsed out of `full_name`, and each `Repository` uses its *own* `owner` (not the organization used for signature verification) to pick the GitHub App/API credentials used for any resulting GitHub API calls: [5](#0-4) [6](#0-5) 

Because `repository.owner.login` and `repository.full_name` are two unrelated JSON keys inside the same request body, an attacker who knows the webhook secret of **any** organization configured in Shipit (Shipit explicitly supports multiple independent per-organization secrets, see `config/secrets.development.shopify.yml`) can set `repository.owner.login` to their own organization (to pass signature verification with a secret they legitimately know) while setting `repository.full_name` to `victim-org/victim-repo`. The signature check only proves the request was signed by *some* configured organization's secret - it does not prove that organization owns the repository the handlers subsequently act on. This is precisely the "organization authenticated vs. repository written" binding named as an acceptable analog class.

### Impact Explanation
By forging `repository.full_name`, an attacker who controls only their own organization's webhook secret can trigger handlers against a completely different organization's `Stack`s/`Repository`. For example, the `push` handler resolves stacks via `repository.full_name` and enqueues `GithubSyncJob` for the victim stack with an attacker-chosen `sha`, and other handlers create/modify `Status`, `Membership`, `PullRequestAssignment`, etc. records tied to the victim repository/stack. Any subsequent GitHub API calls made on behalf of that stack use the *victim* organization's legitimate GitHub App token (`Repository#github_app` uses `owner`, not the org that signed the request), so this results in unauthorized triggers/writes against a repository the attacker never authenticated for - matching the Critical "cross-repository writes / unauthorized deploy" impact bucket.

### Likelihood Explanation
Exploitation requires the attacker to know a valid `webhook_secret` for at least one organization configured on the shared Shipit instance (their own org, in a multi-tenant deployment as documented in `config/secrets.development.shopify.yml`), but no privileged Shipit session, `ApiClient` token, or access to the victim organization's secret. This is a realistic scenario for any Shipit deployment serving multiple GitHub organizations, since each org's own administrators legitimately know their own webhook secret.

### Recommendation
`verify_signature` should not just check that *a* configured secret matches; the organization whose secret validated the signature must be cryptographically bound to the repository the handlers operate on. Concretely, after verifying the signature, re-derive the target repository owner from `repository.full_name` and reject the request (422) if it doesn't match `repository_owner`/`organization.login` used to pick the secret, or better: verify the signature using the secret keyed off `repository.full_name`'s owner rather than the separate `owner.login`/`organization.login` field.

### Proof of Concept
1. Attacker legitimately administers `attacker-org`, one of several organizations configured in this shared Shipit instance, and knows its `webhook_secret`.
2. Attacker crafts a `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` computes `repository_owner = "attacker-org"`, fetches `attacker-org`'s `GitHubApp`, and the HMAC matches → verification passes. [1](#0-0) 
5. `create` dispatches the same payload to the push handler, which resolves the target stack via `payload.dig('repository', 'full_name')` = `"victim-org/victim-repo"`. [4](#0-3) 
6. A `GithubSyncJob` (or equivalent write) is enqueued for the victim stack using the attacker-supplied `sha`, executed with `victim-org`'s own GitHub App credentials - despite the attacker never having authenticated as, or possessing secrets for, `victim-org`.

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

**File:** app/models/shipit/repository.rb (L98-102)
```ruby
    protected

    def github_app
      Shipit.github(organization: owner)
    end
```
