### Title
Webhook signing organization is derived from an unverified payload field distinct from the field used to select the target repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification based on `repository.owner.login` pulled straight out of the still-unverified JSON body. Once the signature check passes, every event `Handler` resolves the repository/stack to act on using a *different* field of that same payload — `repository.full_name` — via `Handler#repository_name`. These two fields are never cross-checked against each other, so the "organization whose secret authenticated the request" is not provably the same as "the repository the handler actually writes/acts against."

### Finding Description
`WebhooksController#verify_signature` computes: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
```

where: [2](#0-1) 

```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`repository_owner` (and thus which organization's `webhook_secret` gets checked) is read from the raw, not-yet-verified body. Meanwhile every concrete handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, `MembershipHandler`, `PullRequest::*Handler`) resolves the target repository/stack via `Handler#repository_name`: [3](#0-2) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`repository.owner.login` (used to pick the verifying secret) and `repository.full_name` (used to pick the acted-upon repository) are independent, attacker-controlled strings inside the same JSON body. The HMAC only proves the payload was signed with *some* organization's `webhook_secret` known to Shipit; it never proves that the organization identified by `owner.login` is the same organization referenced by `full_name`. An actor who legitimately knows one organization's `webhook_secret` (e.g., because they administer that org's GitHub App/webhook configuration in Shipit) can therefore forge a payload where `owner.login` names their own organization (so `Shipit.github(organization: ...)` picks a secret they know) while `full_name` names a completely different, unrelated repository/stack tracked by the same Shipit instance.

This breaks the intended equality: `organization whose webhook_secret authenticated the request == organization/repository that Shipit acts upon`.

### Impact Explanation
Because the signature only vouches for "some org's secret matched," but the acted-upon repository is taken from a sibling field with no binding to that org, an attacker who controls a single onboarded organization's webhook secret can forge events against any other repository/stack known to the Shipit instance:
- `PushHandler` can trigger `stack.sync_github` for an arbitrary victim stack.
- `StatusHandler` can inject arbitrary commit statuses (`state`, `context`, `description`) for arbitrary commit SHAs via `Commit#create_status_from_github!`, which is exactly the kind of status data Shipit uses to gate deployability/CI checks — forging a passing status on an unreviewed commit of a repository the attacker does not own can help an unauthorized/unreviewed commit clear the checks that a legitimate operator relies on before shipping.
- `CheckSuiteHandler`, `MembershipHandler`, and PR handlers can likewise mutate state (team membership, PR/review-stack metadata) belonging to organizations/repositories the attacker was never authorized to send events for.

This crosses a repository trust boundary (an org's credentials being used to act on another org's tracked repository) without any GitHub-side authorization for that cross-repository action, satisfying the "cross-repository writes" / "unauthorized deploy" style impact.

### Likelihood Explanation
Exploitability requires the attacker to know one legitimate `webhook_secret` configured in Shipit — e.g., because they are (or compromise) an org admin who added their own GitHub App/webhook to this Shipit instance, which is a normal, unprivileged-relative-to-other-orgs setup in a multi-tenant Shipit deployment. No `ApiClient` token, session, or GitHub App private key is required beyond the one webhook secret they legitimately possess for their own org; nothing about the host application's mounting is nonstandard here.

### Recommendation
Bind the signature-selection field and the acting field together: verify that `payload.dig('repository', 'owner', 'login')` (or `organization.login`) matches the owner segment of `payload.dig('repository', 'full_name')` before processing, or better, look up the target `Repository` first and only accept the event if the resolved repository's `owner` equals the organization whose secret validated the signature.

### Proof of Concept
1. Attacker administers Org A's GitHub App/webhook configuration registered in this Shipit instance, so they know Org A's `webhook_secret`.
2. Shipit also tracks a stack for `orgB/victim-repo` (Org B, unrelated to the attacker).
3. Attacker crafts a `push` (or `status`) webhook JSON body:
   ```json
   {
     "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" },
     "ref": "refs/heads/master",
     "after": "<attacker-chosen sha>"
   }
   ```
4. Attacker computes `X-Hub-Signature` using Org A's known `webhook_secret` over the raw body and POSTs to `/github/webhooks`.
5. `verify_signature` calls `Shipit.github(organization: "orgA")`, verifies successfully with Org A's secret.
6. `PushHandler#stacks` resolves `Repository.from_github_repo_name("orgB/victim-repo")` and triggers `stack.sync_github(expected_head_sha: ...)` against Org B's stack — an action the attacker has no GitHub-side authorization to trigger for Org B. [4](#0-3)

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
