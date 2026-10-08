# Changelog

## v2.0.3 (2026-10-08) ([release](https://github.com/EsupPortail/esup-otp-manager/releases/tag/v2.0.3))
- **fix** blank page in Manager view [a7f639e](https://github.com/EsupPortail/esup-otp-manager/commit/a7f639e9f8853abc4e370e5c114a4d445cd77576)
- setting to prevent users from deactivating passcode_grid and/or bypass [bcc2820](https://github.com/EsupPortail/esup-otp-manager/commit/bcc2820ad7e108fa3029269df9455f44a08f12c4)
- update dependencies

**Full Changelog**:  https://github.com/EsupPortail/esup-otp-manager/compare/v2.0.2...v2.0.3

## v2.0.2 (2026-10-02) ([release](https://github.com/EsupPortail/esup-otp-manager/releases/tag/v2.0.2))
- update dependencies (**requires "npm install"**)
- improve instructions for users
- allow case-insensitive email regexes (this feature require Node.js 24) [140d0b2](https://github.com/EsupPortail/esup-otp-manager/commit/140d0b28f6f500f8e4796c0ea0c3dd6d6517b1f1)
- fix KeePassXC webauthn registration [2af5c3b](https://github.com/EsupPortail/esup-otp-manager/commit/2af5c3b74e3d87c601307f6bc6ed8e3dbbe35bb9)
- add deactivateAllMethods button on manager view [f2fb754](https://github.com/EsupPortail/esup-otp-manager/commit/f2fb75449c02274989c15ab3ab9869b0cfe8d43a)
- various improvements

**Full Changelog**:  https://github.com/EsupPortail/esup-otp-manager/compare/v2.0.1...v2.0.2

## v2.0.1 (2026-01-22) ([release](https://github.com/EsupPortail/esup-otp-manager/releases/tag/v2.0.1))
- update dependencies (**requires "npm install"**)
- display the actual activation status [ab01a44](https://github.com/EsupPortail/esup-otp-manager/commit/ab01a44ee8300855b1780de07fd5ef20548d6768)
- trigger askActivation when opening a method [a9b82f1](https://github.com/EsupPortail/esup-otp-manager/commit/a9b82f158116efa8a5becf30bfb0919aac26e737)
- various improvements

**Full Changelog**:  https://github.com/EsupPortail/esup-otp-manager/compare/v2.0.0...v2.0.1

## v2.0.0 (2025-09-22) ([release](https://github.com/EsupPortail/esup-otp-manager/releases/tag/v2.0.0))
- feat: dynamic grid method (require esup-otp-api >= v2.0.0) by @floriannari [ae2e95b](https://github.com/EsupPortail/esup-otp-manager/commit/ae2e95bcd233ad7ee98ca50f8a601a4a0c96b209)
- feat: statistics by @vbonamy [567df2f](https://github.com/EsupPortail/esup-otp-manager/commit/567df2f45b90f0dea081c6076d64336d2e5044f4) [c2930cb](https://github.com/EsupPortail/esup-otp-manager/commit/c2930cbb06ecb6f37341c323c5a7bfa99e6e6d4f)
- rename `.jade` files to `.pug` (to avoid deprecation warnings) by @guillomovitch [a0d5370](https://github.com/EsupPortail/esup-otp-manager/commit/a0d537052f5af1e873bf877ceecc5e2698117315) [454285d](https://github.com/EsupPortail/esup-otp-manager/commit/454285dac34e98e9a0e177d8eda31a307d574c57)
- improve a11y by @vbonamy [cfa27d6](https://github.com/EsupPortail/esup-otp-manager/commit/cfa27d6f38aaad402f4543fd7f07b3056596f29a)
- improve logs by @guillomovitch [bd219ea](https://github.com/EsupPortail/esup-otp-manager/commit/bd219ea6ea0acedd0553785e753d07845f4bff2b)
- fix CAS logout by @floriannari [4a52b71](https://github.com/EsupPortail/esup-otp-manager/commit/4a52b712a8b0cef1545f4fdc8cb4bf5e76a41567) [512979c](https://github.com/EsupPortail/esup-otp-manager/commit/512979c64e26f8a5044fbb70e75bedeb98264c63)
- improve user seach (require esup-otp-api >= v2.0.0) by @floriannari [1b1afeb](https://github.com/EsupPortail/esup-otp-manager/commit/1b1afeb604597bdfaa45591eea2481b1e2c297d2)
- chore: update dependencies (requires "npm install") by @floriannari
- feat: support SAML authentication by @guillomovitch and @fouquea [1770a40](https://github.com/EsupPortail/esup-otp-manager/commit/1770a4022dafba1ef8c0721e8caaacbab1776dae)

**Full Changelog**: https://github.com/EsupPortail/esup-otp-manager/compare/v1.5.4...v2.0.0