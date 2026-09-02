## Analysis

Note: `StatusHandler` matches by `sha` alone across all Commits/Stacks (not scoped to `repository_name`), so it isn't the strongest example of the binding break, but `PushHandler` (via `Handler#stacks`) is scoped by `payload.dig('repository', 'full_name')`, which is exactly the field that is never checked against the org used for signature verification.

### Title
Webhook organization used for signature verification is not bound to the repository the payload acts on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to verify a webhook against using `repository_owner`, taken from `params.dig('repository','owner','login')` in the *unverified* JSON body [1](#0-0) . Once the signature check for that organization passes, `create` re-parses the same raw body and dispatches it to event handlers [2](#0-1) . Those handlers, however, do not use `repository.owner.login` to resolve the target stack — they use a separate field, `repository.full_name` [3](#0-2) , which is looked up independently via `Repository.from_github_repo_name` [4](#0-3) . Nothing enforces that `repository.full_name`'s owner matches `repository.owner.login`.

### Finding Description
The binding that should hold is:

`organization authenticated by verify_signature == organization that owns the repository the handler writes to`

In this multi-tenant configuration (explicitly documented and supported, see `docs/setup.md` "Using Multiple Github Applications" and `Shipit.github_app_config`) [5](#0-4) , each organization has its own `webhook_secret`. `verify_signature` picks the `GitHubApp` (and thus the HMAC secret) to check against based solely on `repository.owner.login` (or `organization.login`) from the JSON body [6](#0-5) .

Because the raw POST body is fully attacker-controlled up to the point where it must match a known secret's HMAC, an actor who legitimately knows one configured organization's `webhook_secret` (e.g., an admin of "OrgA", who is unprivileged with respect to "OrgB" and has no Shipit session/API token) can craft a payload where:
- `repository.owner.login = "OrgA"` — selected/verified with OrgA's secret, which the attacker knows,
- `repository.full_name = "OrgB/some-repo"` — the field actually used by `PushHandler`/`Handler#stacks` to resolve which `Stack` to act on [7](#0-6) .

`verify_signature` only checks that the *body* is signed with OrgA's secret; it never checks that `repository.full_name`'s owner equals `repository.owner.login`/`organization.login`. Since `Repository.from_github_repo_name` looks up stacks purely by the `owner/name` parsed out of `full_name` [4](#0-3) , the forged payload is accepted and dispatched against OrgB's stack(s), even though the signature only ever proved authorship for OrgA.

For genuine GitHub-generated webhooks this mismatch cannot occur (GitHub always sets `repository.owner.login` and `repository.full_name` consistently for the repo actually pushed to). The break only becomes reachable because `/webhooks` is a public HTTP endpoint that accepts arbitrary POST bodies (there is no requirement that the request actually originate from GitHub's webhook delivery infrastructure) — the only gate is HMAC validity against *whichever* org the attacker names in the JSON body.

### Impact Explanation
`PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` for every non-archived stack under the spoofed repository's owner/name, matching the branch from the forged `ref` field [8](#0-7) . This lets a party who controls only OrgA's webhook secret force `GithubSyncJob`-style refresh/sync activity against OrgB's stacks. Depending on what `sync_github` triggers downstream (fetching new commits, potentially advancing what is considered deployable), this crosses an organizational trust boundary that the signature was supposed to enforce — an org-scoped write/trigger performed under a different org's stack than the one whose credentials actually authorized the request. This aligns with the High-impact category ("escalation into a repository's state via a boundary the app's own signature check should have enforced"). It falls short of full RCE/token exfiltration because the specific mutation is bounded by what `sync_github` does, but it is a genuine cross-organization/cross-repository action triggered without ever proving authorship for the target org.

### Likelihood Explanation
Exploitation requires an attacker to already hold a valid `webhook_secret` for *some* organization configured on the shared Shipit instance — this is not a Shipit credential (session, `ApiClient` token, `api_clients_secret`) but a per-organization GitHub App webhook secret that an OrgA admin legitimately possesses without being privileged in Shipit or in OrgB. This is a realistic condition specifically in the documented multi-org hosting mode, which the engine ships and documents as a first-class configuration. If only a single organization is configured, or if that organization has no `webhook_secret` set at all, `verify_webhook_signature` degrades to `return true unless webhook_secret` [9](#0-8) , which is an even weaker (but explicitly optional/documented) posture and out of scope as a pure misconfiguration; the multi-org cross-tenant case above does not depend on that misconfiguration.

### Recommendation
In `WebhooksController#verify_signature`/`create`, after verifying the signature for `repository_owner`, additionally enforce that every downstream handler operates only on repositories whose owner matches the organization used to validate the signature — e.g., have `Handler#repository_name`/`Handler#stacks` reject (or the controller reject) any payload where `repository.full_name`'s owner segment does not case-insensitively equal `repository.owner.login`/`organization.login` used in `verify_signature`. This closes the gap between "organization whose secret authenticated this request" and "repository the handler is permitted to act on."

### Proof of Concept
1. Shipit is configured with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md`, "Using Multiple Github Applications").
2. Attacker is an administrator of `OrgA`'s GitHub App and therefore knows `OrgA`'s `webhook_secret` (a routine, unprivileged-relative-to-OrgB credential).
3. Attacker crafts a JSON push payload:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha>",
     "repository": {
       "owner": { "login": "OrgA" },
       "full_name": "OrgB/victim-repo"
     }
   }
   ```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>` and POSTs directly to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `"OrgA"`, loads OrgA's `GitHubApp`, and successfully verifies the signature against OrgA's secret [1](#0-0) .
6. `create` dispatches the same body to `PushHandler`, which resolves stacks via `repository.full_name = "OrgB/victim-repo"` [3](#0-2)  and triggers `sync_github` on OrgB's stack(s) [8](#0-7)  — an action performed on an organization's repository whose secret was never presented.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
