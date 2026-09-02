### Title
Cross-organization webhook forgery: signature is verified against `repository.owner.login`/`organization.login`, but stack lookup and mutation is performed against the unverified `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and thus which HMAC `webhook_secret`) to validate a webhook against using `repository_owner`, computed from `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`). Every downstream handler, however, resolves the target `Repository`/`Stack` using a completely different field: `payload.dig('repository', 'full_name')` [1](#0-0) . Nothing ties these two fields together, so the organization whose secret authenticated the request is not guaranteed to be the organization that owns the repository actually acted upon.

### Finding Description
`Shipit.github(organization:)` looks up a per-organization config (including a distinct `webhook_secret`) via `github_app_config(organization)` [2](#0-1) , and this is exactly the model documented for "Using Multiple Github Applications", where each onboarded organization supplies and knows its own `webhook_secret` [3](#0-2) .

`WebhooksController#verify_signature` picks the verifying app using `repository_owner`: [4](#0-3) 

This only proves the payload was signed by *some org's* known secret, that org being whatever `repository.owner.login` (or `organization.login`) claims. It never confirms that `repository.full_name` (used everywhere downstream to find the target stack) actually belongs to that same organization.

Every handler binds work to a repository from that unchecked field:
- `Handler#repository_name` / `#stacks`: `payload.dig('repository','full_name')` → `Repository.from_github_repo_name` → `Stack` scope [5](#0-4) 
- `PushHandler#process`: syncs a stack's branch to an attacker-chosen `after` SHA via `stack.sync_github(expected_head_sha: params.after)` for any stack under the target repository's branch [6](#0-5) 
- The pull-request family of handlers (`OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `UnlabeledHandler`, `AssignedHandler`, `LabelCapturingHandler`) all resolve `repository` purely from `params.repository.full_name` and then create/archive/unarchive review stacks or mutate pull-request state [7](#0-6) .

Because a Shipit deployment onboards multiple independent GitHub organizations (each with its own `webhook_secret` that only that organization's owner needs to know, per the documented multi-app setup), an organization admin who is unprivileged with respect to Shipit's other tenants can sign an arbitrary JSON body with their own known `webhook_secret`, set `repository.owner.login` to their own org (so `verify_signature` passes), but set `repository.full_name` to `"victim-org/victim-repo"`. `verify_webhook_signature` only HMACs the raw request body against the secret resolved from `repository_owner`; it never validates that `full_name`'s owner segment matches `repository_owner` [8](#0-7) . The signature-verified organization identity and the repository actually mutated are two different bindings that are never checked for equality.

### Impact Explanation
This breaks the trust boundary between tenants of a multi-organization Shipit install: the webhook signature authenticates "this payload came from an app configured for Org A," but the payload content dictates behaviour against Org B's stacks. An attacker who legitimately controls Org A's GitHub App (and therefore its `webhook_secret`, which they configured/know as part of normal onboarding, not a privileged Shipit credential) can forge `push`, `pull_request`, `status`, or `check_suite` events that are processed as if genuinely originating for a repository under Org B. Depending on the target stack's configuration (continuous deployment enabled, CI-required contexts satisfied by forged data), this can drive `sync_github`/status ingestion that unblocks or misdirects deploys for a completely different organization's stack — an unauthorized deploy/state change across a tenant/organization boundary that Shipit is supposed to isolate.

### Likelihood Explanation
Requires the attacker to be a legitimate but low-privilege participant in the multi-tenant Shipit deployment: they must control one onboarded GitHub organization/app configuration (its own `webhook_secret`, which they know from setting it up, not a stolen credential) but must not be a member of, or have access to, the victim organization. This is a realistic tenancy model per Shipit's own multi-app docs. The only obstacle is guessing/knowing the victim's exact `full_name` (`owner/repo`), which is generally public information on GitHub.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), enforce that the organization used to select the webhook secret matches the owner segment of `repository.full_name` (and `organization.login` when present) before dispatching to handlers, rejecting the request with 422 on mismatch.

### Proof of Concept
1. Shipit is configured with two organizations, `org-a` and `org-b`, each with its own GitHub App and `webhook_secret` (`docs/setup.md` "Using Multiple Github Applications").
2. Attacker controls `org-a`'s GitHub App and therefore knows `org-a`'s `webhook_secret`.
3. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(org-a's webhook_secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `"org-a"`, fetches `org-a`'s webhook app, and the signature validates successfully [9](#0-8) .
6. `PushHandler` is invoked with the full payload; it derives the target repository/stacks from `repository.full_name` = `"org-b/victim-repo"` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on `org-b`'s stacks [10](#0-9) [1](#0-0) , even though the signature never proved anything about `org-b`.

### Citations

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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
