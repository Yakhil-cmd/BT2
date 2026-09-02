### Title
Webhook signature verified against the organization named in the payload while the repository acted upon comes from an unverified field in the same payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate the HMAC signature against using `repository_owner`, i.e. `params.dig('repository','owner','login')` (or `organization.login`). Every downstream `Handler` subclass, however, resolves the target `Repository`/`Stack` using a *different* field of the same JSON body: `payload.dig('repository', 'full_name')`. Both fields live in the same attacker-suppliable request body; the controller never checks that they are consistent with each other.

### Finding Description
`verify_signature` computes the trusted org purely from payload content, then checks the raw body's HMAC against that org's `webhook_secret`: [1](#0-0) [2](#0-1) 

Once the signature check passes, every `Handler` looks up the acted-upon repository independently, from a sibling field of the same payload: [3](#0-2) [4](#0-3) 

Because Shipit supports multiple independently-configured GitHub Apps/organizations, each with its own `webhook_secret`, an actor who legitimately controls (and thus knows the `webhook_secret` of) **any one** organization configured in Shipit can forge an arbitrary POST to `/webhooks`:
- set `repository.owner.login` (or `organization.login`) to the organization whose secret they know, so `verify_signature` succeeds,
- set `repository.full_name` to `victim-org/victim-repo`, a completely different, unrelated repository/stack tracked by Shipit under a different organization/App whose secret the attacker does not know.

The equality that should hold — "organization whose signature authenticated the payload" == "organization that owns the repository being written to" — is broken. This is a real signature/authorization binding failure that arises purely from Shipit's own code (which org protects which fields), independent of GitHub's honesty, because Shipit itself never re-derives the trusted org from the same field it uses to select the acted-upon repository, nor verifies they match.

### Impact Explanation
Downstream handlers act on the attacker-chosen `repository.full_name` with no further ownership check:
- `PushHandler#process` calls `stack.sync_github` for stacks under the spoofed repository. [5](#0-4) 
- `StatusHandler#process` writes fabricated commit statuses (`create_status_from_github!`) onto commits of the victim repository, which feed directly into `deployable?` checks used to gate deploys. [6](#0-5) 
- `PullRequest::OpenedHandler`/`ReviewStackAdapter` will **create a `ReviewStack`** for the victim repository/branch if it has review-stack provisioning enabled, which subsequently causes Shipit to check out that branch and execute its `shipit.yml` provisioning/deploy steps on the deploy host. [7](#0-6) [8](#0-7) 

This crosses the "cross-repository writes / unauthorized deploy" impact bar: an org that is only entitled to speak for its own repositories can inject events that create stacks, forge commit statuses, and drive task/deploy execution against a repository belonging to a different, unrelated organization.

### Likelihood Explanation
Exploitation requires only knowledge of the `webhook_secret` for any one organization already configured in a multi-tenant Shipit install (a routine, low-privilege credential for that org's own admins) plus knowledge of the target repository's `owner/name` (public information). No Shipit session, API token, or GitHub write access to the victim repo is needed — the request is a plain unauthenticated HTTP POST to `/webhooks`.

### Recommendation
After computing `repository_owner` for secret selection, require that it matches the owner embedded in `repository.full_name` (and `organization.login` when present) before dispatching to handlers; reject the request if they diverge. Alternatively, have handlers re-derive/re-validate the repository from the same trusted `repository_owner` value used for signature verification rather than trusting `full_name` independently.

### Proof of Concept
1. Shipit is configured with two GitHub Apps/orgs: `attacker-org` (attacker knows its `webhook_secret`) and `victim-org` (tracks repo `victim-org/victim-repo`).
2. Attacker crafts a JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef...",
  "repository": { "owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac(attacker-org's webhook_secret, body)>` and sends `POST /webhooks` with header `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature (using the secret the attacker knows), per [1](#0-0) .
5. `PushHandler#stacks` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `sync_github` on its stacks, per [3](#0-2) , despite the request never being authenticated by `victim-org`'s credentials.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-85)
```ruby
          def create!
            ReviewStack.transaction do
              stack = scope.create!(stack_attributes)
              stack
                .build_pull_request
                .update!(
                  github_pull_request: params.pull_request
                )
            end

            Shipit::ReviewStackProvisioningQueue.add(stack)

            @stack = stack
          end
```
