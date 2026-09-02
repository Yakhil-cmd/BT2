### Title
Cross-organization webhook signature confusion allows one configured GitHub organization to forge push/pull_request/status events for another organization's repositories - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to use for HMAC verification based on `repository.owner.login` (falling back to `organization.login`), but the event handlers that actually act on the payload resolve the target `Stack`/`Repository` from the independent `repository.full_name` field. Nothing binds these two fields together, so on a multi-organization Shipit installation, an org that legitimately authenticates a webhook (knows its own `webhook_secret`) can point `repository.full_name` at a completely different, victim organization's repository and have Shipit act on it.

### Finding Description
`verify_signature` picks the GitHub App/secret purely from the owner login embedded in the unauthenticated payload: [1](#0-0) [2](#0-1) 

The signature check itself is a plain per-organization HMAC compare, with no cross-check that the signed organization matches any other field of the payload: [3](#0-2) 

Once the signature passes, every handler resolves the affected repository/stack from a *different*, unauthenticated field, `repository.full_name`, not the `repository.owner.login`/`organization.login` used for verification: [4](#0-3) 

`PushHandler` uses this to sync arbitrary stacks with an attacker-supplied `after` SHA: [5](#0-4) 

Pull-request handlers use the same unauthenticated `repository.full_name` to resolve the repository and then perform direct state mutations (`archive!`, `unarchive!`, `find_or_create!` review stacks): [6](#0-5) [7](#0-6) 

Shipit explicitly supports hosting multiple, independently-owned GitHub organizations on a single instance, each with its own `app_id`/`webhook_secret`/`private_key`: [8](#0-7) 

The equality binding that should hold is:
`organization that produced a valid signature == organization that owns the repository being acted upon`

Before the attack: for organization A's webhook secret to verify, the payload's `repository.owner.login` (or `organization.login`) must equal "A", and in a genuine GitHub-issued webhook `repository.full_name` also starts with "A/...", so the two fields always agree.

After the attacker's crafted request: `repository.owner.login` is set to "A" (to pass verification with A's known secret) while `repository.full_name` is set to `"B/victim-repo"` (a repository/stack belonging to a different configured organization B). The signature check only validates the first field; the handler only consumes the second. The equality is broken, and Shipit performs authenticated-looking actions on organization B's stack triggered by organization A.

### Impact Explanation
This is a cross-repository/cross-organization write: an org that only controls its own GitHub App installation and webhook secret can force `Stack#sync_github` with an arbitrary `expected_head_sha` on another org's repository, or archive/unarchive/create review stacks belonging to another organization's pull requests, purely by crafting the HTTP body sent to the shared `/webhooks` endpoint. This matches the report's bug class (`_initiateWithdrawImpl` trusting an intermediate value instead of re-validating what's actually acted upon) mapped onto Shipit's deployment-trust model: the organization whose secret authenticated the request is not the same as the repository the handlers subsequently mutate.

### Likelihood Explanation
Requires the target Shipit instance to be configured for multiple GitHub organizations (a documented, supported configuration per `docs/setup.md` and `config/secrets.development.shopify.yml`), and requires the attacker to control one of those configured organizations (i.e., know that organization's own legitimately-issued `webhook_secret`, which they created themselves when setting up their own GitHub App). No access to the victim organization's secret, Shipit session, or `ApiClient` token is needed.

### Recommendation
In `WebhooksController#verify_signature`/`Handler`, bind the verified organization to the acted-upon repository: after choosing `Shipit.github(organization: repository_owner)` for signature verification, re-derive `repository_owner` from `repository.full_name`'s owner segment (not just `repository.owner.login`/`organization.login`) and reject the webhook if the owner segment of `full_name` does not match the organization whose secret verified the signature.

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` and `orgB`, each with distinct `webhook_secret`s (per `config/secrets.development.shopify.yml`), and add `orgB/victim-repo` as a tracked `Repository`/`Stack`.
2. As an operator of `orgA` (who legitimately knows `orgA`'s `webhook_secret` because they configured their own GitHub App), craft:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(orgA_webhook_secret, body)>` and POST to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` to `"orgA"` [2](#0-1)  and verifies successfully using `orgA`'s secret.
5. `PushHandler#process` resolves the stack via `repository.full_name = "orgB/victim-repo"` [9](#0-8)  and calls `stack.sync_github(expected_head_sha: params.after)` [10](#0-9)  — an org-A-originated request has mutated org B's stack state.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
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
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
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
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L41-68)
```ruby
          def process
            return unless respond_to_label_change?

            handle
          end

          private

          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
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
