### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, while the pushed repository/stack is selected using the unauthenticated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization Shipit deployments, `WebhooksController#verify_signature` authenticates an inbound webhook against the GitHub App configured for the organization named in `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`), but the event handlers (e.g. `PushHandler`) determine which `Repository`/`Stack` to act on using `payload.dig('repository', 'full_name')`, a completely separate JSON field that is never covered by the HMAC signature check. Because both fields live inside the same signed JSON body, and the signature is verified with the secret belonging to whatever organization is named in `owner.login`, an attacker who controls a GitHub App/webhook secret for *any* organization configured in Shipit's `secrets.yml` can craft a payload where `repository.owner.login` names their own org (so the signature check passes with their own known secret) while `repository.full_name` names a victim organization's repository. This breaks the intended binding: `organization authenticated == organization whose repository is written`.

### Finding Description
`verify_signature` in `WebhooksController` computes the authenticating organization purely from the payload, not from anything cryptographically bound to which repository is subsequently acted upon: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
```

`repository_owner` is read straight from the request body: [2](#0-1) 

`Shipit.github(organization:)` looks up the GitHub App config (and thus the webhook secret) keyed by that same attacker-controlled string: [3](#0-2) 

Once signature verification passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs the handler with the **entire raw payload**, not just the `owner.login`-scoped portion: [4](#0-3) 

The handler base class and `PushHandler` then resolve the target `Repository`/`Stack` using a *different* field, `repository.full_name`, which was never checked against `repository.owner.login`: [5](#0-4) [6](#0-5) 

In a normal GitHub-originated payload `repository.owner.login` and the owner segment of `repository.full_name` always agree (fixtures confirm this: both are `"Shopify"` / `"Shopify/shipit-engine"`): [7](#0-6) 

But nothing in the engine enforces that agreement. An attacker who is a legitimate GitHub App installer for organization `attacker-org` (and thus knows `attacker-org`'s `webhook_secret` from `secrets.yml`) can POST a forged payload to Shipit's shared `/webhooks` endpoint with:
- `repository.owner.login` = `"attacker-org"` (used only for signature lookup/verification, satisfied with the attacker's own secret)
- `repository.full_name` = `"victim-org/victim-repo"` (used by `PushHandler`/other handlers to select the actual `Stack` to sync/act on)

Because the signature is computed over the raw JSON body with `attacker-org`'s secret, and Shipit verifies it against `attacker-org`'s app, the check succeeds even though the payload's operative fields target a repository belonging to `victim-org`.

### Impact Explanation
This lets an attacker (who legitimately controls one org's GitHub App/webhook secret in a multi-org Shipit install) trigger webhook-driven side effects against stacks belonging to a completely different organization, without ever needing that organization's webhook secret. Concretely, `PushHandler` will enqueue `GithubSyncJob` for any stack matching the forged `full_name`, keying off `expected_head_sha` supplied entirely by the attacker — this can be used to force syncing/deploy-relevant state (last-deployed SHA tracking, undeployed commit computation, CD scheduling triggers) for a victim's stack using attacker-supplied SHAs, and other handlers keyed the same way (status, check_suite, membership, pull_request) are equally exposed to acting on a cross-organization repository. This is a cross-repository write via a spoofed authentication binding, matching the "organization authenticated vs repository written" analog called out for this bug class.

### Likelihood Explanation
Likelihood is High in any Shipit deployment using the documented multi-org GitHub App configuration (`docs/setup.md`, "Using Multiple Github Applications"), which is an explicitly supported and documented feature. Any org admin who is allowed to install a GitHub App pointing at the shared Shipit instance already has everything needed (their own org's `webhook_secret`) to exploit this; no additional privilege escalation, GitHub token theft, or Shipit session is required — only knowledge of one's own configured webhook secret and the ability to POST to the public `/webhooks` endpoint.

### Recommendation
Bind the field used for signature-organization lookup to the same field used for repository resolution, or verify their consistency before processing:
```diff
 def verify_signature
   github_app = Shipit.github(organization: repository_owner)
   verified = github_app.verify_webhook_signature(...)
   head(422) unless verified
+  # Ensure the org that authenticated the payload matches the org that owns
+  # the repository the handlers will act upon.
+  full_name_owner = params.dig('repository', 'full_name')&.split('/')&.first
+  head(422) if full_name_owner && full_name_owner.casecmp(repository_owner).nonzero?
```
More robustly, derive both the authentication org and the target repository consistently from a single trusted field (e.g. always use `repository.full_name`'s owner segment for signature lookup) rather than two independently attacker-controlled JSON paths.

### Proof of Concept
1. Deploy Shipit with multi-org GitHub App config in `secrets.yml` containing both `attacker-org` (with a `webhook_secret` known to the attacker, since they configured that org's GitHub App) and `victim-org` (hosting stack `victim-org/victim-repo`).
2. Attacker builds a push payload body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker chosen sha>",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "attacker-org" }
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(attacker-org_webhook_secret, body)` using their own known secret.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and successfully verifies the signature with the attacker's own secret.
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` and enqueues `GithubSyncJob` for the victim's stack with the attacker-supplied `expected_head_sha`, despite the signature never having been verified against `victim-org`'s webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-23)
```ruby
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
```

**File:** test/fixtures/payloads/push_master.json (L55-59)
```json
  "repository": {
    "id": 17266426,
    "name": "shipit-engine",
    "full_name": "Shopify/shipit-engine",
    "url": "https://github.com/Shopify/shipit-engine",
```
