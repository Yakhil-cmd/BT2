Based on my investigation, I've confirmed a genuine analog to the reported bug class: a field used to select the "authorization" material (the org whose secret verifies the signature) is not the same field used to determine what data gets written (which repository's `Stack` is acted upon).

### Title
Webhook signature is verified against the organization from an unverified payload field while a different, unverified payload field selects the repository/stack that is written - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/webhook secret to use for HMAC verification based on `repository_owner`, a value read straight out of the still-unauthenticated JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`), via `Shipit.github(organization: repository_owner)`. [1](#0-0)  The webhook handlers that actually mutate state (e.g. `PushHandler`) never re-check that this organization matches the repository they act on — they instead resolve the target `Repository`/`Stack` from a completely independent payload field, `payload.dig('repository','full_name')`, via `Handler#repository_name` and `Repository.from_github_repo_name`. [2](#0-1) [3](#0-2) 

### Finding Description
In a multi-organization deployment, `Shipit.github(organization:)` looks up a per-organization config (including a distinct `webhook_secret`) keyed by the organization name supplied to it. [4](#0-3)  The controller derives that organization key from `repository.owner.login`/`organization.login` in the **unverified** request body before signature verification has occurred. [5](#0-4) [6](#0-5) 

The equality the system is supposed to preserve is: `organization authenticated by HMAC == organization that owns the repository being written to`. But nothing enforces that binding — `verify_signature` only proves "this payload was signed with Org A's secret" using whatever `repository.owner.login` the payload claims Org A to be; the subsequent handler (`PushHandler`, pull-request handlers, etc.) reads `repository.full_name` — a separate JSON field the signature check never specifically pinned to Org A — to decide which `Stack` to sync/archive/unarchive. [7](#0-6) 

Concretely: an attacker who is a legitimate, unprivileged member/webhook sender for **Org A** (and thus knows or can trigger genuine signed webhooks with Org A's `webhook_secret`) can craft a payload where `repository.owner.login` (or `organization.login`) is `"OrgA"` (so `verify_signature` resolves and validates against Org A's secret) while `repository.full_name` is set to `"OrgB/victim-repo"` (a repository belonging to a different, unrelated organization configured on the same Shipit instance). Because the HMAC is computed over the raw body and Org A's secret does correctly sign that exact raw body, `verify_signature` passes. The handler then looks up `Shopify::Repository.from_github_repo_name("OrgB/victim-repo")` and operates on **that** stack — e.g. `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` for every non-archived stack on branch `master` under `OrgB/victim-repo`. [8](#0-7) 

This is the same class of bug as the analog target: the value that is cryptographically bound/checked (org used to pick the signing secret) is not the value that governs the actual write (the repository being synced), so the "verified" side and the "acted upon" side can diverge whenever the deployment uses the multi-organization `github:` config with per-org `webhook_secret`s. [9](#0-8) 

### Impact Explanation
An entity with legitimate access to a GitHub App/webhook secret for one configured organization on a shared Shipit instance can forge webhook events (`push`, `pull_request`, `status`, `check_suite`, `membership`) that are attributed to a different organization's repository, causing the engine to act on `Stack`/`ReviewStack` records it does not own — e.g. triggering `GithubSyncJob` on another org's stack, or archiving/unarchiving/creating review stacks for another org's pull requests. This is a cross-repository/cross-organization write performed through a spoofed but "validly signed" webhook, matching the Critical bar of "cross-repository writes" via an authentication-bypass-adjacent flaw (a signature check that authenticates the wrong binding).

### Likelihood Explanation
This only manifests when a Shipit instance is configured with the multi-organization `github:` schema (distinct orgs, each with its own `webhook_secret`) — the documented, supported configuration for shared instances. [10](#0-9)  Given that configuration, the only requirement is knowledge of any one organization's webhook secret (which many people with push access to that org's GitHub App/webhook settings could have), and the ability to POST a crafted JSON body to `/webhooks` — no Shipit session, API token, or GitHub App private key is required.

### Recommendation
Bind the organization used for signature verification to the same field used to resolve the target repository, and verify consistency before dispatching to handlers: verify the payload's `repository.full_name` owner matches the `repository.owner.login`/`organization.login` used to select the `webhook_secret`, and reject (422) if they diverge. More robustly, always verify the signature against every configured organization's app that plausibly could have sent it, or key the secret purely off `repository.full_name`'s owner segment rather than a separately-supplied `owner`/`organization` field, so the field that authorizes and the field that determines effect cannot disagree.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with a distinct `webhook_secret`, and `Repository` records for `OrgA/repoA` and `OrgB/repoB` (each with `Stack`s). [9](#0-8) 
2. As someone who knows `OrgA`'s `webhook_secret` (e.g., an OrgA repo admin who configured the webhook), build a `push` payload body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "full_name": "OrgB/repoB", "owner": { "login": "OrgA" } }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(OrgA_webhook_secret, raw_body)>` and set `X-Github-Event: push`.
4. POST to `/webhooks`. `WebhooksController#repository_owner` returns `"OrgA"` [6](#0-5) , `Shipit.github(organization: "OrgA")` loads OrgA's `webhook_secret`, and `verify_webhook_signature` succeeds because the HMAC was computed correctly with OrgA's secret. [11](#0-10) 
5. `PushHandler#process` then resolves `stacks` via `Repository.from_github_repo_name("OrgB/repoB")` [8](#0-7)  and enqueues `GithubSyncJob` against `OrgB`'s stack with an attacker-controlled `expected_head_sha`, even though the request was never signed by anything associated with `OrgB`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
