### Title
Webhook signature verification is keyed on `repository.owner.login`, but repository/stack targeting is keyed on the unrelated `repository.full_name` field, letting an attacker with any one configured (or secret-less) organization's HMAC secret forge webhooks that write to a different organization's stacks - (`app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate the inbound HMAC against using a value taken straight from the untrusted JSON body (`repository.owner.login`, or `organization.login`), but the handlers that actually act on the payload (sync a stack, archive/unarchive a review stack, create/refresh commit statuses) select the target using a completely different, uncorrelated field of the same untrusted body: `repository.full_name`. Nothing in the code ties the two together, so the "organization whose secret authenticated the request" is not necessarily the "repository that gets written to."

### Finding Description
`verify_signature` picks the signing organization from the payload itself: [1](#0-0) [2](#0-1) 

That organization is used only to look up which secret to HMAC-verify with: [3](#0-2) 

Multiple independent organizations, each with their own (optional) `webhook_secret`, are an explicitly supported configuration: [4](#0-3) 

Note that `verify_webhook_signature` returns `true` outright when `webhook_secret` is blank for that org - i.e. an org configured without a secret bypasses authentication entirely: [5](#0-4) 

Once signature verification passes, the raw payload is dispatched to handlers unmodified: [6](#0-5) 

Every handler that resolves which `Stack`/`Repository` to mutate reads a *different* field - `repository.full_name` - with no cross-check against the `repository.owner.login`/`organization.login` value that was used for authentication: [7](#0-6) [8](#0-7) [9](#0-8) 

The `status` handler is even more permissive - it doesn't scope by repository at all, only by commit SHA across the whole install: [10](#0-9) 

So the equality that is supposed to hold - "the organization whose secret authenticated this delivery" == "the repository/stack this delivery is allowed to mutate" - is never enforced. An attacker who knows (or is the legitimate owner of) any one organization tracked by this Shipit instance - including one deliberately or accidentally configured with no `webhook_secret` - can POST directly to the public, unauthenticated `/webhooks` endpoint with:
- `repository.owner.login` (or `organization.login`) = an org whose secret they control/know or that has no secret configured (passes `verify_signature`)
- `repository.full_name` = `"victim-org/victim-repo"` (used by every handler to pick the actual `Stack`/`Repository`/commits to act on)

and have that forged, validly-"signed" delivery drive real side effects against a stack it was never authorized to touch: triggering `stack.sync_github` (push), archiving/unarchiving/creating review stacks (pull_request events), or injecting arbitrary commit statuses (status/check_suite events) for any commit SHA in the install, which can influence `ci.require` deploy-gating logic described in the docs.

### Impact Explanation
This breaks the deployment-trust binding between the authenticated organization and the repository actually written, allowing cross-repository/cross-organization writes without possessing the victim organization's webhook secret. Depending on which handler is abused this can: force out-of-band syncs, silently create/destroy review stacks, or forge commit statuses that satisfy CI-gating requirements later relied upon before a deploy - i.e., unauthorized state changes on a repository/stack the attacker does not control and was never granted access to. This matches the "Critical: cross-repository writes / unauthorized deploy" impact bucket, since it is a full authentication-binding bypass reachable by an anonymous network client with no Shipit session, `ApiClient` token, or GitHub write access to the target repository - only knowledge of (or ownership of) any one organization entry present in this Shipit installation's config, which may not even require a secret.

### Likelihood Explanation
Multi-organization Shipit deployments are an officially documented and supported configuration, and it is common for teams to leave `webhook_secret` unset on some entries (the docs explicitly call it optional per-organization). In such deployments the attack requires no privileged credential at all for the victim org - only the ability to send an HTTP POST with a crafted JSON body, and, at most, knowledge of the secret for a single unrelated organization tracked by the same instance. This makes exploitation practical wherever more than one organization/repository is tracked by a single Shipit deployment.

### Recommendation
After parsing the payload in `create`/`verify_signature`, cross-validate that the organization used to select the webhook secret is actually consistent with the repository being acted upon (e.g., derive both the signing key selection and the repository/stack lookup from the same trusted field, and reject the delivery if `repository.full_name`'s owner segment does not match `repository.owner.login`/`organization.login`). Additionally, scope `StatusHandler#process` to commits belonging to the repository named in the payload rather than matching SHA globally across all tracked stacks.

### Proof of Concept
1. Configure Shipit (as documented) with two organizations, `orgA` (attacker-known secret, or no secret) and `orgB` (victim, tracks stack `orgB/victim-repo`).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
   signed with `orgA`'s secret (or unsigned if `orgA` has no `webhook_secret`).
3. `verify_signature` resolves `Shipit.github(organization: "orgA")` and passes because the HMAC (or blank-secret bypass) is valid for `orgA`.
4. `PushHandler#process` looks up `Repository.from_github_repo_name("orgB/victim-repo")` and calls `stack.sync_github(expected_head_sha: "deadbeef")` on the victim's stack - despite the request never being authenticated by `orgB`'s secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
