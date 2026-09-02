### Title
Webhook Signature Verified Against a Different Organization Than the Repository the Payload Mutates - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp`/`webhook_secret` to validate a webhook against using the attacker-controlled field `repository.owner.login` (or `organization.login`), while every `Handler` that actually mutates state resolves its target `Stack`/`Repository` using the *separate*, also attacker-controlled field `repository.full_name`. Because these two JSON fields are never cross-checked for consistency, and because `verify_webhook_signature` treats an organization with no configured `webhook_secret` as automatically verified, an attacker can forge an unsigned webhook whose `repository.owner.login` names an org with no secret configured, while `repository.full_name` names a repository that belongs to a different, "protected" org. The request passes signature verification but is processed as if it legitimately targets the protected repository's stacks.

### Finding Description
Signature verification: [1](#0-0) 
`repository_owner` is derived purely from the JSON body: [2](#0-1) 

`GitHubApp#verify_webhook_signature` short-circuits to `true` whenever the resolved organization has no `webhook_secret` configured: [3](#0-2) 

This is a documented, supported configuration — multiple orgs can be configured per instance, and any of them may leave `webhook_secret` blank: [4](#0-3) 

Once the request clears `verify_signature`, `create` dispatches the raw, unverified-for-content JSON body to every registered handler: [5](#0-4) 

Every handler's target `Stack`s are resolved from `repository.full_name` — a field that was never involved in the signature check: [6](#0-5) 

`PushHandler`, for example, uses this to trigger a GitHub sync on any stack under the resolved repository, using attacker-supplied `ref`/`after` values: [7](#0-6) 

The `status` handler similarly creates a `CommitStatus` record for an arbitrary commit sha it looks up by matching `repository.full_name` and `sha`, as shown by the existing test that a "status" webhook event creates a `Status` for a specific commit: [8](#0-7) 

**The broken binding, expressed as an equality that no longer holds:**
`organization used to select the webhook_secret for signature verification (repository.owner.login)` == `repository whose stacks/commits the handler mutates (repository.full_name)`

Before the attack, for any legitimately-delivered GitHub webhook these two fields always agree, because GitHub itself populates both from the same repository object. After the attacker's forged request, they diverge: the verification path is satisfied by an org with no secret, while the mutation path acts on a repository belonging to an entirely different, secured org.

### Impact Explanation
This is an authentication-bypass class issue: the signature check is supposed to prove "this payload really came from GitHub for this organization/repository," but the field it checks and the field the handler trusts for the *actual mutation* are decoupled. Concretely reachable, high-value handlers include:
- `StatusHandler`, which lets an attacker forge a `success` CI status for an arbitrary commit sha under a protected repository's stack, defeating `ci.require` checks and enabling an unauthorized deploy of an unreviewed/failing commit — this maps to the Critical "unauthorized deploy" impact category.
- `PushHandler`/`check_suite` handlers, which can trigger unscheduled syncs/refreshes against protected stacks, and combined with continuous-deployment configuration, can trigger deploys from attacker-chosen shas without valid GitHub authorization.

No credentials, GitHub App private key, or repository write access are required — the attacker only needs the Shipit instance to have at least one configured GitHub organization with `webhook_secret` left blank (an explicitly documented, supported configuration) alongside at least one other organization/repository that is actually protected and deploy-managed by that same Shipit instance.

### Likelihood Explanation
Likelihood depends on operator configuration: it requires the Shipit deployment to manage multiple GitHub organizations (a supported multi-org configuration shown in `config/secrets.development.shopify.yml` and `test/dummy/config/secrets_double_github_app.yml`) where at least one organization has no `webhook_secret` set. This is plausible in real deployments (e.g., a low-risk/staging org left without a webhook secret for convenience) while a production org is properly secured. Given that, exploitation requires only crafting a single unauthenticated HTTP POST to `/webhooks` — no session, token, or GitHub credential of any kind.

### Recommendation
Do not select the verification organization from unauthenticated request content that differs from the field trusted for mutation. Concretely:
- Derive both the verification-org lookup and the acting-repository lookup from the same, single payload field (e.g., always use `repository.full_name`'s owner segment for both), or
- Reject webhooks where `repository.owner.login` and the owner segment of `repository.full_name` disagree, and
- Treat a missing `webhook_secret` for an organization as "verification not possible" rather than "verification succeeds," at minimum refusing to act on any repository belonging to a *different* organization than the one whose (lack of) secret produced the "verified" result.

### Proof of Concept
Assume a Shipit instance configured with two orgs: `OrgNoSecret` (webhook_secret blank) and `OrgProtected` (webhook_secret set, hosts a real stack with `ci.require` configured for continuous deployment).

1. Attacker sends, with no valid `X-Hub-Signature` (or any garbage value):
```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=deadbeef

{
  "sha": "<sha of a commit under OrgProtected/target-repo that is pending/failing CI>",
  "state": "success",
  "context": "required-ci-check",
  "repository": {
     "owner": { "login": "OrgNoSecret" },
     "full_name": "OrgProtected/target-repo"
  }
}
```
2. `verify_signature` computes `repository_owner = "OrgNoSecret"`, fetches that org's `GitHubApp`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally — the request is accepted.
3. `StatusHandler` (a registered handler for `status` events, matching the behavior exercised in `test/controllers/webhooks_controller_test.rb`) resolves the target commit/stack via `repository.full_name = "OrgProtected/target-repo"`, and writes a `Status` record marking the required CI context as `success` for the attacker-chosen sha.
4. If continuous deployment is enabled and this satisfies `ci.require`, the next deploy cycle deploys the attacker-chosen commit without any real CI having passed — an unauthorized deploy achieved with zero credentials.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```
