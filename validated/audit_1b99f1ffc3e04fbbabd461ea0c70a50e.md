Confirmed: Shipit supports a genuine multi-tenant configuration where `secrets.github` contains multiple organizations, each with its own `webhook_secret`, and `Shipit.github(organization:)` looks up the config keyed on the organization name provided at call time. [1](#0-0) 

### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but the repository acted upon is taken from the unrelated `repository.full_name` field, allowing cross-organization stack manipulation - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's webhook secret to validate the HMAC signature against using `params.dig('repository', 'owner', 'login')` (or `organization.login`). [2](#0-1) [3](#0-2)  Once the signature check passes, the event handlers (e.g. `PushHandler`) resolve the target `Stack`/`Repository` using a completely different field of the same payload: `payload.dig('repository', 'full_name')` via `Handler#repository_name`/`Handler#stacks`. [4](#0-3)  Because Shipit's GitHub App configuration is genuinely multi-tenant (`Shipit.github_app_config` looks up a per-organization block, each with its own `webhook_secret`), an attacker who legitimately controls a GitHub organization/App installation registered in Shipit's config can craft a payload whose `repository.owner.login` matches their own org (so the signature check succeeds using a secret they know) while `repository.full_name` names a repository belonging to a *different* organization's stack. [5](#0-4) 

### Finding Description
The binding that should hold is: `organization authenticated by the HMAC == organization whose repository/stack is mutated by the handler`. The controller breaks this equality by deriving the "authenticating organization" from one payload key (`repository.owner.login`) and letting the handler operate on a repository derived from an entirely independent key (`repository.full_name`), with no cross-check that the two agree.

- `verify_signature` extracts `repository_owner` from the JSON body and calls `Shipit.github(organization: repository_owner)` to fetch that organization's `GitHubApp`, then verifies the raw body's HMAC using that organization's `webhook_secret`. [6](#0-5) 
- Once verified, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs handlers such as `PushHandler`, which resolves the affected stacks purely from `payload.dig('repository', 'full_name')`, with no re-validation that this repository belongs to the same organization whose secret validated the signature. [7](#0-6) [8](#0-7) [4](#0-3) 
- Since a valid signature only proves "this body was HMAC'd with organization X's secret" and X is picked by an attacker-controlled field, an attacker who owns/administers a Shipit-registered GitHub organization (and therefore knows that organization's `webhook_secret`) can forge a `repository.full_name` pointing at a stack belonging to a completely different, victim organization, and Shipit will accept and act on it as if GitHub had sent it for that victim repository.

### Impact Explanation
This breaks the deployment-trust binding between "the organization that authenticated the request" and "the repository being written to" (the analog explicitly listed in scope). A forged `push` event can trigger `GithubSyncJob`/`Stack#sync_github` against another organization's stack, and similarly crafted `pull_request`, `status`, `check_suite`, or `membership` events can inject/modify commit statuses, labels, review-stack lifecycle events, or team memberships for stacks/repositories the attacker does not own, all while the request passes signature verification. This is a cross-repository write achieved without possessing that repository's own webhook secret — matching the "cross-repository writes" Critical-impact criterion.

### Likelihood Explanation
Exploitability requires the attacker to control at least one organization/GitHub App installation that is itself configured in the target Shipit instance's `secrets.github` multi-tenant config (so they legitimately know one `webhook_secret`), which is a realistic scenario for any Shipit deployment onboarding multiple orgs/customers, none of which are supposed to trust each other's webhook secrets for controlling each other's stacks. No privileged Shipit session, API token, or GitHub write access to the *victim* repository is needed — only the ability to send an HTTP POST to `/webhooks` with a body signed by the attacker's own known organization secret.

### Recommendation
After verifying the signature, re-derive the organization strictly from the same field used for verification (`repository.owner.login` / `organization.login`) and cross-check it against the organization implied by `repository.full_name` (and any other org-scoped identifiers used by handlers) before dispatching to handlers; reject the webhook if they disagree. Alternatively, bind webhook secrets per-repository (not per-organization) or pass the already-verified organization/repository context explicitly into `Handler.call` instead of re-parsing untrusted fields independently in `Handler#repository_name`.

### Proof of Concept
1. Attacker controls GitHub organization `attacker-org`, which is a legitimately configured tenant in Shipit's `secrets.github` (with its own `webhook_secret`, e.g. via a GitHub App they installed for their own repos).
2. Attacker crafts a `push` webhook JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-controlled-sha>",
     "repository": {
       "owner": { "login": "attacker-org" },
       "full_name": "victim-org/victim-repo"
     }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org's webhook_secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `attacker-org`, fetches `attacker-org`'s `webhook_secret`, and the signature check passes. [2](#0-1) 
5. `PushHandler#process` (via `Handler#stacks`/`#repository_name`) looks up `victim-org/victim-repo` and enqueues `Stack#sync_github` for the victim's stack, using the attacker-supplied `after` SHA — despite the signature never having been checked against the victim organization's secret. [8](#0-7) [4](#0-3)

### Citations

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
