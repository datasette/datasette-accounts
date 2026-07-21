# Build deltas — where reality diverged from plan/reference (and why)

Each verified during main-loop review. The plan tickets under
`plans/auth2/tickets/` have been annotated where it matters; this page is
the consolidated list.

1. **core-01: enabled re-check is external-only.** My ticket over-claimed
   ("finish_login: enabled re-check" unqualified); the reference never
   re-checks enabled on the local path. Local routes rely on provider_gate
   + password-flow checks; the load-bearing kill switch guards the external
   path (landed core-03).
2. **core-01: provenance deferred.** `provider` columns needed m009, so
   core-01 shipped migration-free; `finish_login` kept `provider_key` in
   its signature unstamped until core-03.
3. **core-02: set_password_complete uses mint_session, not finish_login.**
   Reference-faithful (JSON body shape predates must_change_password).
4. **core-02 → core-05: carried debt.** Reference M2 bundled latent
   password-enabled gates; excluded from core-02 (zero-behavior bar),
   landed in core-05 where disable became reachable —
   `LoginPageData.password_enabled` goes to core-06.
5. **core-03: link-intent ordering hardened beyond its reference.** M3
   checked link/step-up intents only on the unmatched branch; we dispatch
   before the matched-identity mint (the final reference's M4 ordering) so
   core-04 couldn't inherit the takeover trap. core-04 ticket says: don't
   move it back.
6. **core-03: D5 rewrite included.** m009 renames `registration_enabled` →
   `provider:password:signups` ('1'→'approval');
   get/set_registration_enabled became shims (set_ delegating to
   set_provider_signups as of core-05); CLI `registration` is now a
   documented alias.
7. **core-04: page-data surfacing deferred to core-06** (IdentityRow,
   AccountPageData fields, admin-list identities): backend endpoints +
   state machine landed complete; one reference page-data test omitted →
   core-06.
8. **core-05: break-glass is not a guard bypass.** Enabling is simply never
   guarded; CLI hits the internal DB directly, so shell access always
   restores password login. Guard prevents ever reaching zero enabled.
9. **core-01 env fix:** stale editable install of the demo package (from
   the old branch layout) crashed all plugin loading in the dev venv;
   uninstalled. If plugin discovery ever explodes with ModuleNotFoundError,
   check `uv pip list` for ghosts.
10. **Scaffolds: no conftest in bluesky repo** (reference suite needs none)
    — deliberate deviation from the provisioning-notes recipe.
