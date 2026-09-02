This confirms the multi-org configuration model: `Shipit.github(organization:)` maps directly onto keys in `secrets.github` (a hash of organization slugs, each with its own `webhook_secret`), and `github_app_config` looks up the config purely by the organization name that was passed in, with no restriction that this org must "own" any particular repository. [1](#0-0) 

### Title
Cross-organization webhook forgery lets one configured GitHub org's admin fake CI status / push events for any repository across all orgs - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which HMAC secret to check a webhook's signature against based on `repository_owner`, a value read straight out of the untrusted, not-yet-verified JSON payload (`params.dig('repository','owner','login')` or the `organization.login` fallback). Once the signature check passes, the payload is handed to event handlers that instead trust an entirely different field of the same payload — `repository.full_name` — to decide which `Repository`/`Stack`/`Commit` the event acts on. Nothing ties these two fields together, so a signature that is valid for organization A's webhook secret can be paired with a `repository.full_name` pointing at organization B's repository.

### Finding Description
`Shipit.github(organization:)` looks up per-organization GitHub App configuration (including `webhook_secret`) purely by name, out of `secrets.github` [1](#0-0) . In multi-org deployments (as documented in `config/secrets.development.shopify.yml`), each org has its own webhook secret.

`WebhooksController#verify_signature` uses this to select the secret: [2](#0-1) 

The organization used to pick the secret comes straight from the payload before any authentication has occurred: [3](#0-2) 

Once `verified` is true, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the full raw payload to handlers [4](#0-3) . Every default handler resolves the target repository from a **different** payload field, `repository.full_name`, via `Handler#repository_name`/`#stacks`: [5](#0-4) 

For example, `StatusHandler` writes a commit status for whatever `sha` is present on any commit Shipit already knows about, based on the (unchecked) match between the signing org and the acted-on repository: [6](#0-5) 

and `PushHandler` triggers `stack.sync_github` for stacks under the branch named in the payload: [7](#0-6) 

Because `repository_owner` (used to authenticate) and `repository.full_name` (used to act) are independent, unconstrained fields inside the same attacker-crafted JSON body, an actor who legitimately controls **any one** of the configured GitHub organizations (i.e., is an admin of that org's installed GitHub App and therefore knows its `webhook_secret`) can sign a payload with their own org's secret while setting `repository.full_name` to a repository belonging to a **different** organization tracked by the same Shipit instance. `verify_signature` only checks that the signature matches the secret for the org named in the payload's `owner.login` — it never checks that this org is the one that actually owns `repository.full_name`.

This breaks exactly the binding class called out in scope: "an organization that authenticated versus the repository that is written."

### Impact Explanation
Using this gap, an admin of Organization A (untrusted with respect to Organization B's repositories) can:
- Forge a `status` event reporting `state: "success"` for any commit SHA belonging to Organization B's tracked stacks, which Shipit's `Commit#create_status_from_github!` records as-is and which feeds directly into CI-gating (`ci.require`) and continuous merge/deploy logic (`stack.schedule_merges` is triggered when status becomes `pending`/`success`). This can cause an unauthorized deploy or merge of code that never actually passed real CI on GitHub.
- Forge `push`/`check_suite`/`pull_request`/`membership` events referencing Organization B's repositories or teams, causing spurious syncs, review-stack archiving/unarchiving, or team/membership churn for a tenant the attacker has no legitimate relationship with.

This matches the "Critical" bucket defined in scope ("an unauthorized deploy, rollback or merge") because forged success statuses can let unreviewed/unapproved code satisfy Shipit's CI gates and proceed to deployment.

### Likelihood Explanation
This requires no Shipit session, ApiClient token, or GitHub access to the victim organization/repository at all — only that the attacker administers (or has push access sufficient to configure a webhook secret for) any one of the other GitHub organizations configured in the same Shipit instance's `secrets.github` multi-org map. In any Shipit deployment shared across multiple, mutually-untrusting GitHub organizations (the exact scenario the multi-org config schema exists for), this is directly reachable by simply crafting a JSON body with mismatched `repository.owner.login` and `repository.full_name` fields and a correctly-computed `X-Hub-Signature` using the attacker's own org secret.

### Recommendation
After `verify_signature` succeeds, re-derive the organization from `repository.full_name` (or `repository.owner.login` consistently) and reject the webhook (422) if the org actually used to authenticate the signature does not match the owner segment of `repository.full_name` that the handlers will act upon. Alternatively, pass the authenticated organization explicitly into `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params, authenticated_organization:) }` and have `Handler#stacks`/`#repository_name` reject any payload whose repository owner does not equal the authenticated organization.

### Proof of Concept
1. Shipit is configured with two GitHub orgs, `attacker-org` and `victim-org`, each with its own GitHub App and `webhook_secret` (per `config/secrets.development.shopify.yml` schema).
2. Attacker administers `attacker-org`'s GitHub App and therefore knows `attacker-org`'s `webhook_secret`.
3. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "<victim commit sha tracked by Shipit>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<hmac using attacker-org's webhook_secret>` over the raw body and POSTs it to `/webhooks` with `X-Github-Event: status`.
5. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and validates successfully against the attacker's own secret.
6. `StatusHandler#process` looks up `Commit.where(sha: ...)` (a commit belonging to `victim-org/victim-repo`, unrelated to the authenticating org) and records the forged `success` status, potentially unblocking CI-gated merges/deploys for `victim-org`'s stack.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
