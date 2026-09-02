This confirms the key binding gap in the multi-org webhook flow. Now I have enough to write the analog finding.

### Title
Webhook signature verified against `repository.owner.login`'s GitHub App but repository actions keyed on unverified `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and its `webhook_secret`) using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` (or `organization.login`). Every event handler, however, resolves the target `Repository`/`Stack` from a different, independently-attacker-controlled field: `payload.dig('repository', 'full_name')` in `Handler#repository_name`. In multi-org deployments (`Shipit.github_organizations`, `github_app_config`), these two fields are never cross-checked, so the org whose secret authenticates the request is not bound to the repository whose data actually gets mutated.

### Finding Description
`verify_signature` in [1](#0-0)  looks up the app config via `repository_owner`: [2](#0-1) 

That call flows into `Shipit.github(organization:)`, which in a multi-org setup fetches a distinct `webhook_secret` per organization from `secrets.github`: [3](#0-2) 

`GitHubApp#verify_webhook_signature` trivially returns `true` when that organization's `webhook_secret` is blank: [4](#0-3) 

Once signature verification passes, `WebhooksController#create` dispatches the entire raw JSON body — unmodified and with no re-validation of `repository.owner.login` — to the handlers: [5](#0-4) 

Handlers resolve the acted-upon repository from `repository.full_name`, a sibling field of `repository.owner.login` inside the same JSON object, but never compared against it: [6](#0-5) 

Because the signature check binds to `repository.owner.login` and the mutation binds to `repository.full_name`, an attacker who can produce a validly-signed (or unsigned, if that org has no `webhook_secret` configured) payload for **any one** onboarded organization can set `repository.full_name` to `OtherOrg/other-repo` and have the handler operate on a stack belonging to a completely different, unrelated organization. This is the structural analog of the reported `sfnProcessTradeDispute` bug: the field the signature covers (`repository.owner.login`) is not the field the write path acts on (`repository.full_name`).

### Impact Explanation
This breaks the equality `organization authenticated == repository written`. For example, `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` for every stack of the resolved (spoofable) repository [7](#0-6) , and `PullRequest::ClosedHandler#process` archives review stacks of the resolved repository [8](#0-7) . A validly-authenticated webhook for OrgA can be crafted to instead reference `OrgB/repo` in `repository.full_name`, causing cross-organization/cross-repository state changes (sync/deploy triggers, review-stack archival) that the org whose credentials were actually checked has no authority over.

### Likelihood Explanation
Exploitability requires only the ability to send one validly-signed (or unsigned-if-secret-absent) webhook payload for any organization configured in the multi-org `secrets.github` map — a realistic scenario since Shipit is explicitly designed to host many organizations behind one instance, and `webhook_secret` is documented as optional (`# nil` in `config/secrets.development.example.yml`). No repository write access, session, or API token is required — only knowledge of, or default absence of, one org's webhook secret.

### Recommendation
After computing `repository_owner` for signature verification, require that `repository.full_name.split('/').first` (or `organization.login` for org-level events) matches `repository_owner` before dispatching to handlers; reject the payload otherwise.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` (webhook_secret unset) and `OrgB` (has a stack tracked in Shipit).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-controlled sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/target-repo" }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "OrgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of signature.
4. `PushHandler` resolves the stack via `Repository.from_github_repo_name("OrgB/target-repo")` and enqueues `sync_github`, mutating OrgB's stack without any credential belonging to OrgB.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
