### Title
Webhook signature is verified against the requesting organization's secret, but `StatusHandler` writes CI status to any `Commit` in the database by SHA alone, enabling cross-repository/cross-organization forged CI statuses - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to validate the HMAC signature with based on `repository_owner`, itself read from the payload's `repository.owner.login` (or `organization.login`). Once that check passes, the `status` event handler (`StatusHandler`) never re-checks that field: it looks up commits purely by `sha` across the entire Shipit database and writes a status onto every match, regardless of which repository/organization that commit belongs to. The binding the engine relies on — "the organization whose secret authenticated this request" == "the repository/commit being written to" — is never enforced past signature verification.

### Finding Description
`verify_signature` picks the app config to verify against using only the attacker-supplied `repository_owner` field: [1](#0-0) 

In a multi-organization Shipit deployment, each organization has its own independent `webhook_secret`: [2](#0-1) 

The signature only proves the request was signed with *that org's* secret; it says nothing about the rest of the payload (e.g. `sha`, or a `repository.full_name` that names a different repo). Most handlers re-derive the target stacks via `Repository.from_github_repo_name(repository_name)`, i.e. `payload.dig('repository', 'full_name')`: [3](#0-2) 

`StatusHandler`, however, does not use that scoping at all — it queries `Commit.where(sha: params.sha)` globally and writes a status to every matching commit: [4](#0-3) 

Since git SHAs are public and easily obtainable (e.g. from a public repository's commit history, or a repo the attacker can see), an org admin who has legitimately configured their own GitHub App / webhook secret for organization A can sign an arbitrary `status` payload with A's secret, but set `sha` to a commit belonging to organization B's repository (already known to Shipit because B's stack tracked that commit). `verify_signature` only checks that the signature matches org A's secret for `repository_owner = "A"`; it has no knowledge that the `sha` field targets a commit under B. The request passes verification and `StatusHandler#process` writes an attacker-controlled CI status (e.g. `state: "success"`, arbitrary `context`) onto organization B's commit.

This is the direct analog of the Perennial bug: the vault (here, the webhook controller) verifies against one piece of recorded/trusted state (the org's secret == the org field) while a different, unguarded field (`sha` / commit ownership) is used downstream to decide what gets mutated — a version-vs-reality mismatch that lets state intended for one context ("the vault's owned market") be applied to another ("a different repository's commit").

### Impact Explanation
CI statuses recorded via `create_status_from_github!` feed into `ci.require` gating that determines whether a commit is deployable in Shipit (documented in `README.md`, `ci.require`). By forging a `success` status for a required context on an arbitrary commit belonging to a stack the attacker does not own, an unprivileged-with-respect-to-victim attacker (who only administers their own, unrelated GitHub App installation on the same multi-tenant Shipit instance) can satisfy deploy-blocking CI checks for another organization's repository, enabling that commit to be merged/deployed via Shipit's continuous delivery — an unauthorized deploy, and at minimum an unauthorized cross-repository write of falsified CI state into Shipit's database.

### Likelihood Explanation
The only requirement is administrative control over one's own organization's GitHub App/webhook secret within a Shipit installation configured for multiple GitHub organizations (a documented, supported configuration per `secrets.development.example.yml` / `docs/setup.md`). No access to the victim organization, no GitHub write access to the victim repo, and no Shipit session/token is required — only knowledge of the target commit's SHA, which is public.

### Recommendation
In `StatusHandler` (and any other handler relying on payload fields not covered by the org-selection check), scope the lookup by the verified organization/repository, not by `sha` alone — e.g. resolve `stacks` via `Repository.from_github_repo_name(repository_name)` first, then constrain `commit.where(sha:)` to those stacks' commits, mirroring the pattern already used by `PushHandler`/`CheckSuiteHandler`. More generally, `verify_signature` should ensure the `repository_owner` used to select the signing secret is consistent with the repository/organization actually referenced by the rest of the payload before handlers execute.

### Proof of Concept
1. Attacker legitimately administers a Shipit-connected GitHub App for `org-attacker`, and thus knows `org-attacker`'s `webhook_secret`.
2. Attacker observes (publicly, or via prior tracking) a commit SHA `deadbeef...` belonging to `org-victim/app`, a repository tracked by the same Shipit instance with a stack requiring CI context `ci/tests`.
3. Attacker crafts a `status` event payload:
   ```json
   {
     "sha": "deadbeef...",
     "state": "success",
     "context": "ci/tests",
     "repository": { "owner": { "login": "org-attacker" } }
   }
   ```
4. Attacker computes `X-Hub-Signature: sha1=<hmac(org-attacker secret, body)>` and POSTs to `/github/webhooks` with `X-Github-Event: status`.
5. `verify_signature` resolves `repository_owner = "org-attacker"`, fetches `org-attacker`'s `GitHubApp`, and successfully verifies the signature [5](#0-4) .
6. `StatusHandler#process` runs `Commit.where(sha: "deadbeef...")` and creates a `success` status on `org-victim/app`'s commit [4](#0-3) , satisfying `org-victim`'s `ci.require` gate despite the attacker never having any relationship with `org-victim`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
