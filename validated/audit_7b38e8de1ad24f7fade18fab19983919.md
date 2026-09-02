## Analysis

The Dash DKG report describes messages being accepted/retained by identity fields inside a payload that were never actually checked against the transport-level authentication. Shipit-engine has a structurally identical flaw in its webhook intake path: the field used to *select and verify* the signing secret is taken from the same untrusted JSON body that is later used to *decide what gets mutated*, and per-organization signature verification is bypassable simply by targeting an organization that has no `webhook_secret` configured.

### Finding Description

`WebhooksController#verify_signature` picks which GitHub App (and therefore which `webhook_secret`) to verify the incoming signature against by reading `repository_owner`, which is parsed directly out of the unauthenticated request body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`), before any cryptographic check has occurred: [1](#0-0) [2](#0-1) 

`GithubApp#verify_webhook_signature` unconditionally returns `true`, skipping HMAC comparison entirely, whenever the selected organization's config has no `webhook_secret` set: [3](#0-2) 

Shipit explicitly supports multiple GitHub organizations, each with an independently configured (optional) `webhook_secret`: [4](#0-3) 

Because the org used to pick the verification secret (`repository.owner.login` / `organization.login`) and the org/repo that the event handlers actually act on (`repository.full_name`, used by `PushHandler`, membership handlers, etc.) are two independent, attacker-controlled fields inside the same unauthenticated JSON body, an attacker can:

1. Name `repository.owner.login`/`organization.login` as an organization that has **no** `webhook_secret` configured (verification short-circuits to `true`).
2. Set `repository.full_name` (for repo events) or `team`/`member` (for the `membership` event) to reference a stack/team that actually belongs to a *different*, secret-protected organization.

The `membership` event handler creates `Team` and `Membership` records purely from event payload data, with no re-validation that the acting organization matches the team's real organization: [5](#0-4) 

Those `Membership`/`Team` records are what Shipit's OAuth login flow consults against the configured `github.oauth.teams` allow-list to authorize dashboard access: [6](#0-5) 

### Binding broken

`organization authenticated by webhook signature` ≠ `organization/repository/team actually written by the handler`. Before the attack, only events genuinely signed by the org's own `webhook_secret` can mutate that org's `Stack`/`Team`/`Membership` state. After the attacker's crafted request, an org with no `webhook_secret` (verification returns `true` unconditionally) is used to smuggle in a forged event whose payload content (`full_name`, `team`, `member`) targets a stack or team that belongs to a completely different, secret-protected organization.

### Impact Explanation

Forging a `membership` event lets an unauthenticated attacker create arbitrary `Team`/`Membership` records associating any GitHub login with any team name/slug. If that team name matches an entry in `Shipit.github_teams` (the OAuth allow-list), the attacker escalates into `Shipit.github_teams` authorization for a GitHub identity of their choosing — matching the explicit High-severity bucket "escalation into `Shipit.github_teams` authorization." Forging `push`/`status`/`check_suite`/`pull_request` events for a secret-protected org's repos similarly permits unauthorized stack syncs, status writes, and PR-driven `archive!`/`unarchive!` actions on that org's stacks without ever knowing that org's real `webhook_secret`.

### Likelihood Explanation

Requires: (a) more than one GitHub organization configured (explicitly documented/supported), and (b) at least one configured organization without a `webhook_secret` (also explicitly documented as a valid, `nil`-able configuration in `config/secrets.development.example.yml` and `docs/setup.md`). No credentials, sessions, or tokens are required — only knowledge of the target org/team names, which are discoverable from the public GitHub UI.

### Recommendation

- Never allow request-body content to select which secret is used to authenticate that same request; instead, verify the signature against every configured secret (or a fixed/default one) and only then trust body-derived organization/repository fields.
- Do not silently treat a missing `webhook_secret` as "signature always valid" — require an explicit opt-out flag, or refuse events for orgs with no secret configured.
- After verification, cross-check that `repository.full_name`'s owner (or the `membership` event's `organization.login`) matches the organization whose secret actually validated the signature, rejecting mismatches.

### Proof of Concept

Assume `config/secrets.yml` configures organizations `secure-org` (with a `webhook_secret`) and `open-org` (with `webhook_secret: nil`), and `secure-org` is listed in `github.oauth.teams` for dashboard access.

```
POST /github/webhooks
X-Github-Event: membership
X-Hub-Signature: sha1=anything   # ignored, open-org has no secret

{
  "action": "added",
  "organization": { "login": "open-org" },
  "team": { "id": 1, "name": "secure-org-admins", "slug": "secure-org-admins", "url": "https://github.com/x" },
  "member": { "login": "attacker-github-handle" }
}
```

Because `repository_owner`/`organization.login` resolves to `open-org`, `verify_webhook_signature` returns `true` unconditionally per [7](#0-6) , and the membership handler creates a `Membership` binding `attacker-github-handle` to team `secure-org-admins` — the same team name gating access under `secure-org`'s `oauth.teams` list, granting the attacker's GitHub identity authenticated dashboard access it should never have obtained.

**Uncertainty:** I could not retrieve `app/models/shipit/webhooks/handlers/membership/*.rb`, the `Team`/`Membership` models, or the OmniAuth callback controller this session (ran out of tool iterations), so I could not directly confirm whether `Team`/`Membership` are scoped per-organization in the schema or whether the OAuth login check matches purely by team name/slug without an org column. This PoC's exact mechanics should be validated against those files before treating it as fully confirmed, but the core authentication-selection flaw in `webhooks_controller.rb` and `github_app.rb` is confirmed directly from the code shown above.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L123-129)
```markdown
**`github.oauth.id`** and **`github.oauth.secret`** In your GitHub App settings, on the `General` section, you can find these two at the bottom of the page.

**`github.oauth.teams`** optional, required only if you want to restrict access to a set of GitHub teams.

If it's missing, the Shipit installation will be public unless you setup another authentication method.

After you change the list of teams, you have to invoke `bin/rake teams:fetch` to prefetch the team members.
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

**File:** test/controllers/webhooks_controller_test.rb (L129-148)
```ruby
    test ":membership creates the mentioned team on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Team.count }, 1 do
        post :create, as: :json, body: membership_params.merge(team: {
                                                                 id: 48,
                                                                 name: 'Ouiche Cooks',
                                                                 slug: 'ouiche-cooks',
                                                                 url: 'https://example.com'
                                                               }).to_json
        assert_response :ok
      end
    end

    test ":membership creates the mentioned user on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      Shipit.github.api.expects(:user).with('george').returns(george)
      assert_difference -> { User.count }, 1 do
        post :create, body: membership_params.merge(member: { login: 'george' }).to_json, as: :json
        assert_response :ok
      end
```
