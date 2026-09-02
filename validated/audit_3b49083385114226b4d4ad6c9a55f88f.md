### Title
Webhook signature is validated against a secret selected by an attacker-controlled organization field that is decoupled from the repository field actually acted upon - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
The reported KIBToken bug is a "temporary variable" trust binding failure: the value used to authorize a change (`temp_variable`) is not the same value that is finally written back, letting `from == to` desynchronize the check from the effect. The same class of bug exists in `WebhooksController#verify_signature`: the value used to select/validate the authorizing secret (`repository_owner`, derived from the JSON payload) is not cryptographically bound to the value later used by the event handlers to decide which repository/stack is mutated (`repository.full_name`, read from the same payload by `Handler#repository_name`). Because HMAC verification only proves "whoever produced this signature knows *a* secret for the organization named in the payload," not "the payload's `repository.full_name` belongs to that organization," a party who legitimately possesses the webhook secret for one configured GitHub organization can forge a body whose `repository.full_name` names a stack that belongs to a different, unrelated organization/repository configured on the same Shipit instance.

### Finding Description
`WebhooksController#verify_signature` resolves which GitHub App/secret to validate against purely from attacker-controlled JSON: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of the untrusted payload (`params.dig('repository', 'owner', 'login')`), and `Shipit.github(organization: repository_owner)` looks up the per-organization webhook secret via `github_app_config`: [3](#0-2) 

Signature validation itself is a plain HMAC-SHA1 comparison over the full raw body using that resolved secret: [4](#0-3) 

Once the signature check passes, every event handler independently re-reads the repository identity from the same untrusted body via `Handler#repository_name`/`#stacks`, which is based on `repository.full_name`, a *different* JSON key than the one used to select the signing secret (`repository.owner.login`): [5](#0-4) 

Nothing in `verify_signature` or in `Handler` cross-checks that `repository.full_name`'s owner segment matches `repository.owner.login` (or `organization.login`). Concretely:
- `PushHandler` triggers `stack.sync_github` for whatever stack matches `repository.full_name`: [6](#0-5) 
- `StatusHandler` writes a CI/status record for any commit matching `sha`, again scoped only by `repository.full_name` at the point the payload is parsed, not by any signature-bound owner: [7](#0-6) 

Binding broken (as an equality that should hold but doesn't):
`organization_used_to_select_and_verify_the_HMAC_secret == owner(repository_full_name_acted_on_by_handlers)`

Before the attacker's request: for a legitimate GitHub-originated webhook, GitHub always signs with the secret belonging to the exact repository/org the event is about, so the two sides are naturally equal.
After the attacker's crafted request: an entity that legitimately knows/controls organization A's webhook secret (e.g., they administer their own GitHub App installation configured under Shipit's multi-org `secrets.github` map) can POST directly to `/webhooks` with `repository.owner.login = "OrgA"` (so `verify_signature` fetches and matches OrgA's secret) but `repository.full_name = "OrgB/private-repo"`, sign the raw body with OrgA's known secret, and have the request pass signature verification while the handler operates on OrgB's stack.

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" trust boundary called out for this bug class. A tenant who legitimately owns one organization's webhook secret in a multi-org Shipit deployment can forge webhook events that mutate state belonging to a completely different, unauthorized organization/repository: trigger `GithubSyncJob` (which fetches commits/marks stacks accessible or inaccessible) via `PushHandler`, inject arbitrary commit statuses via `StatusHandler` (which feeds into `Commit#deployable?` checks that gate deploy safety), or drive PR label/membership/team side effects in handlers such as `pull_request/*_handler.rb` and `membership_handler.rb` for a repository/org they have no legitimate relationship with — a cross-repository/cross-tenant write. Depending on how a specific deployment's `shipit.yml`/deploy gating treats status checks, this can facilitate an unauthorized deploy by falsifying a "green" CI status for a commit that never actually passed CI, matching the "unauthorized deploy" impact bucket.

### Likelihood Explanation
Exploitability is limited to environments actually using the multi-organization `secrets.github` schema (multiple orgs, each with distinct `webhook_secret`) — a supported and documented configuration in `docs/setup.md`, not a misconfiguration. Within that setup, any org owner who legitimately controls their own webhook secret (an expected, unprivileged-relative-to-other-tenants position — they don't need an `ApiClient` token, GitHub App private key, TLS interception, or Shipit session) can immediately exploit this by sending a single crafted POST to `/webhooks`, since nothing else gates the mismatch between the signing-org field and the acted-upon-repository field.

### Recommendation
After signature verification succeeds, re-derive/validate the repository actually referenced by the payload (`repository.full_name`) against the same organization that was used to select/verify the webhook secret (e.g., require `repository.full_name.split('/').first.casecmp(repository_owner) == 0`, or resolve the `Repository`/`Stack` only within the verified organization's scope) before dispatching to any `Handler`. Equivalently, make `Handler#stacks`/`#repository_name` scope lookups by the verified organization, not solely by the raw `full_name` string taken from the same untrusted body used for repository selection.

### Proof of Concept
1. Deploy Shipit with the multi-org config schema, e.g. `secrets.github = { orga: { webhook_secret: "secretA", ... }, orgb: { webhook_secret: "secretB", ... } }`, with `Stack`s registered under repositories owned by both `OrgA` and `OrgB`.
2. As an actor who legitimately knows `secretA` (e.g., OrgA's own GitHub App admin), build a JSON push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/private-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(secretA, raw_body)>` and POST to `/webhooks` with header `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `repository_owner = "OrgA"`, fetches OrgA's `secretA`, and the HMAC matches → request is accepted (`app/controllers/shipit/webhooks_controller.rb:24-38`).
5. `PushHandler#process` (via `Handler#repository_name`/`#stacks`, `app/models/shipit/webhooks/handlers/handler.rb:32-38`) resolves the target stack from `repository.full_name = "OrgB/private-repo"` and calls `stack.sync_github(expected_head_sha: ...)`, mutating OrgB's stack state despite the request only ever being authorized by OrgA's secret.

Note: I was unable to fully trace how a specific `shipit.yml`'s deploy safety checks interpret forged `StatusHandler`-created statuses in this exact index snapshot (e.g., exact `Commit#deployable?`/CI-gate logic), so the "unauthorized deploy" escalation path via forged statuses is plausible but not independently confirmed end-to-end here; the cross-org `PushHandler`/state-mutation path above is confirmed directly from the cited code.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
