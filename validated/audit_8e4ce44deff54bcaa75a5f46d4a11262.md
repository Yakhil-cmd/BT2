### Title
Confused-deputy webhook signature verification lets an unauthenticated attacker forge `status`/`push` events for repositories they don't control, enabling unauthorized deploys - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's HMAC secret to verify the inbound webhook against by reading `repository.owner.login` (or `organization.login`) out of the **unverified** JSON body itself. But the handlers that actually act on the event (`PushHandler`, `StatusHandler`, etc.) read a **different** field from that same unverified body (`repository.full_name`, or in the `status` handler's case, no repository scoping at all — just `sha`). Because Shipit explicitly supports multi-organization deployments with independent, optional, per-organization `webhook_secret`s, an attacker can pick an organization key whose secret is blank (an explicitly documented, supported state: "Webhook secret (optional)") to make signature verification a no-op, while pointing the actually-processed fields at a completely different, properly-secured organization/repository/commit that Shipit tracks.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb` verifies webhooks like this: [1](#0-0) 

`repository_owner` is taken straight from the untrusted JSON payload: [2](#0-1) 

`GitHubApp#verify_webhook_signature` treats a blank/unset secret as automatically verified: [3](#0-2) 

Shipit explicitly documents and supports per-organization webhook secrets that can independently be left unset, in a shared `/webhooks` endpoint serving all configured organizations: [4](#0-3) [5](#0-4) 

Meanwhile, the event handlers determine *which repository/commit to act on* from an entirely different payload field than the one used to pick the signing secret: [6](#0-5) [7](#0-6) 

Worse, `StatusHandler` doesn't scope by repository at all — it matches **any** `Commit` row in the entire database sharing the attacker-supplied `sha`, across all stacks/organizations: [8](#0-7) 

This mirrors the M-7 bug class: the binding used to authorize/verify a request (`organization` chosen for HMAC secret lookup) is not the same binding used to determine what gets acted upon (`repository.full_name` / `sha` used to pick the target). The equality that should hold — "the organization whose secret verified this signature" == "the repository/commit that gets mutated" — does not hold, because both values come from the same attacker-controlled, only-partially-verified JSON body, and the app allows verification to be trivially satisfied for at least one organization key.

### Impact Explanation
A `Status` webhook flowing through this path lets an attacker mark **any tracked commit** as `state: success` via `Commit#create_status_from_github!` regardless of which repository it actually belongs to: [9](#0-8) 

Flipping a commit to `success` can make it `deployable?` and, combined with `continuous_deployment`, triggers `ProcessMergeRequestsJob`/deploy scheduling: [10](#0-9) [11](#0-10) 

This is a confused-deputy path to an **unauthorized deploy** on a repository/organization the attacker has no legitimate access to, satisfying the required "unauthorized deploy" impact bucket, without needing any Shipit session, `ApiClient` token, or the target organization's actual `webhook_secret`.

### Likelihood Explanation
Requires only that the Shipit deployment (a) tracks more than one GitHub organization (a documented, supported configuration) and (b) at least one configured organization has no `webhook_secret` set (explicitly documented as "(optional)"). No credentials, GitHub access, or Shipit session of any kind are required — only the ability to POST to the public `/webhooks` endpoint.

### Recommendation
Do not select the verification secret from an attacker-controlled field that differs from the field used by handlers to determine the target. Either: (1) require every configured organization in a multi-org setup to have a non-blank `webhook_secret` and reject requests where verification cannot occur, or (2) after choosing the app/secret used for verification, re-validate that `repository.full_name`'s owner matches the organization whose secret verified the signature, and reject mismatches; and (3) scope `StatusHandler` (and other handlers) to only touch commits that belong to the repository/organization the verified signature was actually associated with, not merely by `sha`.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `OrgA` (properly secured, tracks a sensitive repo/stack with `continuous_deployment: true`) and `OrgB` (left with `webhook_secret: # nil`, as shown in the shipped example config).
2. As an anonymous, unauthenticated attacker, `POST /webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "<sha of an existing pending/failing commit tracked under OrgA's stack>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "OrgB" }, "full_name": "OrgA/sensitive-repo" }
}
```
3. `verify_signature` computes `Shipit.github(organization: "OrgB")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally regardless of (or absent) `X-Hub-Signature`.
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and calls `create_status_from_github!`, creating a `success` status on OrgA's commit.
5. If this flips the commit's aggregate status to `success` and `OrgA`'s stack has `continuous_deployment` enabled, a deploy is scheduled/triggered — an unauthorized deploy carried out entirely by an attacker with no access to OrgA at all.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
  end
end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```
