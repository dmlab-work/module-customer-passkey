# Changelog

## [0.2.1] — 2026-10-25

### Fixed
- Guests opening My Account → Passkeys got HTTP 500 instead of the login redirect.
- Non-RFC 4122 AAGUIDs (Chrome, Google Password Manager) were wiped on first passkey sign-in.

### Changed
- Rejected passkeys are logged as warnings, not critical errors.
- Tested on Magento 2.4.9 and PHP 8.5.

## [0.2.0] — 2026-10-18

### Security
- Challenges are bound to their ceremony: a login-minted challenge can no longer complete a registration.
- Adding a passkey requires a recent sign-in (`general/reauth_window`, default 300 s) or the current password.
- Login options are discoverable-only: `allowCredentials` is always empty, so the response no longer
  reveals whether an email exists or leaks its credential ids. Registration always requires a resident key.

### Added
- Customer email when a passkey is added or removed (`notification/*` config, two email templates).
- Admin "Passkeys" tab on customer edit with revoke (ACL `DmLab_CustomerPasskey::manage`).
- `i18n/en_US.csv`, `CONTRIBUTING.md`, `.gitattributes`.

### Fixed
- Private content (minicart, customer name) refreshes after passkey login.

### Changed
- Declared all Composer dependencies and the `module.xml` sequence; dropped `setup_version`.
- `composer.json` no longer hard-codes `version` (taken from the release tag).
- Requires `web-auth/webauthn-lib ^5.3.5`.
- Passkeys registered as non-resident cannot sign in; affected customers must re-enrol.

## [0.1.1] — 2026-10-04
- Version bump only.

## [0.1.0] — 2026-09-26
- Initial release (`dmlab/module-customer-passkey`): passkey registration, discoverable login and
  My Account management.
