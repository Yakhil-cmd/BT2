### Title
Session Fixation via GitHub OAuth Callback Binding Authenticated Identity to Pre-Existing Session ID — (File: `app/controllers/shipit/github_authentication_controller.rb`)

### Summary
`GithubAuthenticationController#callback` binds a freshly-authenticated GitHub identity to whatever session already exists in the browser, without calling `reset_session` first. This lets an attacker "fixate" a victim's session ID before the victim logs in through GitHub; once the victim completes the OAuth flow, the attacker's known session ID becomes authenticated as the victim, giving the attacker full access to the victim's Shipit session (deploys, rollbacks, task triggers, etc.).

### Finding Description
The callback action reads the OmniAuth payload and unconditionally writes to the *current* session: [1](#0-0) 

```ruby
def callback
  return_url = request.env['omniauth.origin'] || root_path
  auth = request.env['omniauth.auth']

  return render('failed', layout: false) if auth.blank?

  session[:user_id] = sign_in_github(auth)
  session[:authenticated] = true
  redirect_to(return_url)
end
```

Note that `logout` explicitly calls `reset_session`: [2](#0-1) 

but `callback` — the point where a session transitions from anonymous to authenticated — does not. This is the same class of "incomplete binding" bug as the CVE referenced: one input is validated/trusted (the OmniAuth-verified GitHub identity), while a related but distinct value that the rest of the system actually keys off (the session cookie / `session_id`, which was never re-issued) is left untouched and can be attacker-controlled ahead of time. `UserRequiredMiddleware` and downstream controllers key all authorization purely off `session[:user_id]` / `session[:authenticated]`: [3](#0-2) 

### Impact Explanation
This maps to the explicitly accepted High-impact category "session fixation / forced OAuth completion." Successful exploitation gives the attacker a fully authenticated session as the victim — equivalent to an account takeover of any Shipit user (potentially privileged, if the victim is a member of an authorized GitHub team per `Shipit.github_teams`), enabling unauthorized deploys, rollbacks, task triggers, and reading of stack/deploy state without ever needing the victim's or an org's credentials.

### Likelihood Explanation
Rails' cookie-store session middleware does not regenerate the session ID automatically on privilege change; regeneration must be done explicitly via `reset_session`. Because Shipit does not set `session.rotate` semantics here, and no other mitigation (e.g., forcing a new session id pre-login) was found in `app/controllers/concerns/shipit/authentication.rb` for the callback path, a classic session-fixation attack (e.g., attacker sends victim a link that pre-sets a known session cookie, or exploits any mechanism that lets an unauthenticated visitor obtain/keep a session ID, then waits for the victim to complete GitHub OAuth) is plausible. This does not require a Shipit session, an `ApiClient` token, a webhook secret, or any repository access from the attacker — only getting the victim to complete the OAuth login while using the attacker-controlled session identifier.

### Recommendation
Call `reset_session` (or otherwise regenerate the session ID) inside `GithubAuthenticationController#callback` before setting `session[:user_id]`/`session[:authenticated]`, mirroring what `logout` already does, so no pre-authentication session ID survives the privilege transition.

### Proof of Concept
1. Attacker visits the Shipit host (unauthenticated) and obtains a session cookie `S` (or fixates one via any mechanism that sets a session cookie before authentication, e.g., a crafted link that forces a session to be created).
2. Attacker sends the victim a link to `/github/auth/github` (or a login link) while ensuring the victim's browser carries session cookie `S` (e.g., via a subdomain cookie-setting trick or by getting the victim to open a link with the attacker's session cookie already injected through a separate flaw, or simply by sharing a device/browser profile).
3. Victim completes the GitHub OAuth flow; `GithubAuthenticationController#callback` fires and executes `session[:user_id] = sign_in_github(auth); session[:authenticated] = true` on session `S` without rotating it.
4. Attacker, still holding session cookie `S`, is now authenticated as the victim and can perform deploys/rollbacks/task triggers under the victim's identity.

Note: I could not fully verify how session cookie `S` would be delivered/fixated onto the victim's browser (i.e., whether the host application's deployment sets `SameSite`/`Secure` attributes or exposes another cookie-setting primitive), since that depends on deployment-specific session store configuration outside `app/controllers/shipit/github_authentication_controller.rb`. The core application-level defect — omission of `reset_session` in the login/callback path — is confirmed directly in the code above.

### Citations

**File:** app/controllers/shipit/github_authentication_controller.rb (L7-21)
```ruby
    def callback
      return_url = request.env['omniauth.origin'] || root_path
      auth = request.env['omniauth.auth']

      return render('failed', layout: false) if auth.blank?

      session[:user_id] = sign_in_github(auth)

      # We need to set this so that the /events and /sidekiq endpoint
      # which leverage `UserRequiredMiddleware` will recognize the user
      # is authenticated.
      session[:authenticated] = true

      redirect_to(return_url)
    end
```

**File:** app/controllers/shipit/github_authentication_controller.rb (L23-26)
```ruby
    def logout
      reset_session
      redirect_to(root_path)
    end
```
