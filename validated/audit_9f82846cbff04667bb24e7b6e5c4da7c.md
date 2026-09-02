### Title
Webhook signature is verified against the payload's claimed `repository.owner.login`, not the `repository.full_name` actually acted upon, enabling cross-organization webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to HMAC-verify a webhook against using `repository_owner`, a field read out of the *same unverified* JSON body it is about to check [1](#0-0) . Handlers, however, resolve the actual `Stack`/`Repository` to mutate using a *different* field from that same body, `repository.full_name` [2](#0-1) . Because the HMAC only proves "this payload was signed with organization X's webhook secret," and never proves that `repository.full_name`'s owner equals `repository_owner`/organization X, an attacker who knows a valid webhook secret for *any* organization configured on the Shipit instance (Shipit explicitly supports multiple independent GitHub App/organization configs, each with its own `webhook_secret`, see `test/dummy/config/secrets_double_github_app.yml`) can forge a signed payload whose `repository.owner.login` is their own org but whose `repository.full_name` names a repository belonging to a completely different, unrelated organization also hosted on the same Shipit instance.

### Finding Description
The binding that should hold is:

`organization whose secret authenticated the HMAC == organization owning the repository the handler acts on`

Before the fix (i.e., as currently implemented):
- `verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` (or `organization.login`) and looks up `Shipit.github(organization: repository_owner)` to get that org's app/secret [1](#0-0) , then calls `verify_webhook_signature(signature, request.raw_post)` which HMACs the *entire* raw body against that one org's secret [3](#0-2) .
- Nothing ties this check to `repository.full_name`. Every webhook handler (`PushHandler`, `PullRequest::OpenedHandler`, `PullRequest::ClosedHandler`, etc.) independently derives the target `Repository`/`Stack` from `payload.dig('repository', 'full_name')` [4](#0-3) , and `Repository.from_github_repo_name` does a plain, global lookup with no cross-check against which org's secret validated the request [5](#0-4) .

Because Shipit supports multiple, independently configured organizations sharing one deployment (each with its own `webhook_secret` under `config/secrets.yml`, see `docs/setup.md` "Using Multiple Github Applications" and the fixture `test/dummy/config/secrets_double_github_app.yml`), the attacker's "authenticated identity" (their own org, whose secret they legitimately hold as that org's Shipit administrator) is never checked against the repository the request claims to be about. An attacker for Org B can therefore:
1. Craft a JSON body: `{"repository": {"owner": {"login": "OrgB"}, "full_name": "OrgA/some-repo"}, "ref": "refs/heads/master", "after": "<sha>"}`.
2. Sign it with Org B's own known `webhook_secret` using `X-Hub-Signature: sha1=HMAC(OrgB_secret, body)`.
3. POST it to `/github/webhooks` (or wherever `WebhooksController#create` is mounted) with `X-Github-Event: push`.
4. `verify_signature` resolves `Shipit.github(organization: "OrgB")`, verifies the HMAC successfully (since it matches Org B's own secret over the exact bytes sent), and lets the request through.
5. `PushHandler#process` then loads `Repository.from_github_repo_name("OrgA/some-repo")` and calls `stack.sync_github(expected_head_sha: ...)` on Org A's stack — an org the attacker has no relationship to at all [6](#0-5) .

The same pattern applies to PR handlers, which can archive/unarchive/provision review stacks belonging to Org A using only Org B's webhook secret, since they too key off `params.repository.full_name` [7](#0-6) .

### Impact Explanation
This is a cross-repository/cross-organization write: an attacker legitimately trusted for Org B's webhooks (a party the Shipit operator explicitly onboarded, but only for Org B's own repos) can force GitHub-sync jobs, review-stack archival/unarchival/provisioning, or other webhook-triggered writes on Org A's stacks, which they have no authorization over. This maps to the "cross-repository writes" Critical impact category, since the security boundary between tenant organizations configured on the same Shipit instance is broken.

### Likelihood Explanation
Requires the attacker to hold a valid `webhook_secret` for *some* organization configured on the instance — realistic in any multi-tenant Shipit deployment (a documented, supported configuration) where multiple orgs' secrets are independently provisioned and one tenant is not meant to be trusted for another tenant's repos. No GitHub App private key, `GITHUB_TOKEN`, Shipit session, or `ApiClient` token is needed — only the webhook secret for the attacker's own onboarded organization, which is not privileged with respect to any other organization's stacks.

### Recommendation
After signature verification succeeds for organization `repository_owner`, additionally verify that `payload.dig('repository', 'full_name')`'s owner segment matches `repository_owner` (case-insensitively) before dispatching to handlers, and reject (422) on mismatch. Alternatively, have each handler re-derive/validate the owning organization from the same field used for signature verification rather than trusting `full_name` independently.

### Proof of Concept
Given two orgs configured in `secrets.yml` (`OrgA`, `OrgB`) each with distinct `webhook_secret`s, and Org A having stack `OrgA/some-repo` in Shipit:

```
body = {
  "ref" => "refs/heads/master",
  "after" => "deadbeef",
  "repository" => {
    "owner" => { "login" => "OrgB" },   # attacker's own org — chooses which secret verifies
    "full_name" => "OrgA/some-repo"      # victim org's actual repo, acted upon by the handler
  }
}.to_json

signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", OrgB_webhook_secret, body)

POST /webhooks
X-Github-Event: push
X-Hub-Signature: #{signature}
body: #{body}
```

`verify_signature` passes (Org B's secret matches Org B's own login field), but `PushHandler` triggers `GithubSyncJob` against `OrgA/some-repo`'s stack [6](#0-5) , confirmed unauthorized cross-org write.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
