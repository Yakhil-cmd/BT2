### Title
Webhook signature is validated against an organization derived from an attacker-controlled payload field that is disjoint from the repository field the handlers act on, allowing cross-organization webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In multi-organization Shipit deployments, each GitHub organization has its own GitHub App configuration and `webhook_secret` [1](#0-0) . `WebhooksController#verify_signature` selects which organization's secret to validate the request against using `repository_owner`, a value read directly out of the untrusted JSON body (`params.dig('repository', 'owner', 'login')` or the `organization.login` fallback) [2](#0-1) . However, the handlers that actually act on the payload resolve the target repository/stack from a *different* field of the same body, `payload.dig('repository', 'full_name')` [3](#0-2) . Because both fields live in the same attacker-controlled JSON body, and the signature is only used to prove the request was signed by *some* organization's secret (not that the two fields are consistent), an attacker who legitimately controls the webhook secret for one organization can forge a signed request whose `repository.owner.login` points at their own org (so the correct secret is picked and verification passes) while `repository.full_name` points at a victim organization's repository.

### Finding Description
- `verify_signature` picks the GitHub App config via `Shipit.github(organization: repository_owner)`, and `repository_owner` comes straight out of the request body: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [4](#0-3) .
- `Shipit.github_app_config(organization)` looks up a distinct secret per organization key under `secrets.github` [5](#0-4) , confirming Shipit supports (and expects) multiple organizations with independent webhook secrets.
- `verify_webhook_signature` HMACs the *entire raw body* with the secret selected above [6](#0-5) . This proves the body was signed with *a* known secret, but the secret is chosen using a value from inside that same body.
- After verification, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs handlers over the full JSON body [7](#0-6) . Every handler resolves its target stacks via `Handler#repository_name`, which reads `payload.dig('repository', 'full_name')` — a field completely independent of `repository.owner.login` used for authentication [3](#0-2) .
- `Repository.from_github_repo_name` splits this attacker-supplied `full_name` on `/` and looks up any repository/owner pair in the database, with no cross-check against `repository_owner` [8](#0-7) .

The binding that should hold is: `organization that authenticated the request == owner of the repository the handler writes to`. This engine breaks that equality because both values are read from independent, attacker-controlled JSON keys inside a single signed body, and only one of them (`repository.owner.login`) is used to pick the verification secret while the other (`repository.full_name`) is what handlers actually act on.

### Impact Explanation
A party that legitimately possesses the webhook secret for organization A (i.e., a Shipit admin who configured/owns a GitHub App installation for org A, or anyone who has obtained that one secret) can forge webhook events (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.) that are authenticated as "from org A" but whose `repository.full_name` targets any other organization/repository already known to the Shipit instance (org B). For example, `PushHandler` calls `stack.sync_github(expected_head_sha:)` for every non-archived stack matching the forged branch/repo [9](#0-8) , letting the attacker drive sync/deploy-triggering state changes (continuous delivery, commit status changes, PR/merge-queue transitions) on a victim organization's stacks without ever having credentials for that organization. This is a cross-organization/cross-repository write achieved purely by forging webhook payload content, matching the Critical "cross-repository writes" / unauthorized deploy category.

### Likelihood Explanation
Requires the attacker to control (or have been granted) a legitimate GitHub App / webhook secret for at least one organization configured on the Shipit instance — i.e., they must already be a trusted party for org A. This is analogous to the original report's requirement of a "few whitelisted parties" (the `ADD_TOKEN_TO_COLLECTION_ROLE`/`initialBidder`), which was still judged Medium/valid. Here the equivalent trusted party is any organization admin who owns a webhook secret in a multi-org Shipit setup, and the exploit requires no code execution, just crafting a JSON body with mismatched `repository.owner.login` and `repository.full_name` fields and computing the HMAC with their own known secret.

### Recommendation
After signature verification succeeds, re-derive `repository_owner` from the resolved target repository (`payload.dig('repository', 'full_name')`'s owner segment) and reject the request (422) if it does not match the organization whose secret validated the signature. Alternatively, bind webhook secrets to `Repository` records rather than to top-level organization keys, and verify that the owner segment of `full_name` equals the authenticated organization before dispatching to any handler.

### Proof of Concept
1. Shipit is configured with two organizations, `org-a` and `org-b`, each with its own `webhook_secret` (per `secrets.github.org_a.webhook_secret` / `secrets.github.org_b.webhook_secret`) [5](#0-4) .
2. Attacker has legitimate access to `org-a`'s webhook secret (e.g., they are an org-a admin who set up the GitHub App).
3. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha already known to attacker>",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(org-a-webhook-secret, raw_body)>` and POSTs to `/webhooks`.
5. `verify_signature` computes `repository_owner = "org-a"`, fetches `org-a`'s config, verifies successfully since the attacker signed with the real `org-a` secret [10](#0-9) .
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("org-b/victim-repo")`, finds org-b's real stacks, and calls `stack.sync_github(expected_head_sha:)` on them [9](#0-8) [8](#0-7)  — a state-changing action on org-b's stack triggered entirely by org-a's credentials.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
