# 🔐 MFA Controller – Summary (NestJS)

This summary outlines key functionality of the `MfaController` for handling Multi-Factor Authentication using TOTP and Email.

---

## 📌 Endpoints Overview

### ✅ `POST /mfa/enable`
- Initiates MFA setup (`TOTP`, `EMAIL`, `SMS`).
- Checks if another MFA type is already enabled:
  - ❌ **Already enabled with different type** → Rejects with error.
  - 🔁 **Pending setup of different type** → Resets and allows new setup.
- TOTP:
  - 🔐 Returns QR code & secret.
- Email:
  - 📧 Sends code to email.
- SMS:
  - 📵 Not implemented yet.
- Invalid type:
  - 💥 Returns unsupported MFA error.

---

### 🔐 `POST /mfa/verify`
- Verifies code from TOTP app or Email.
- ✅ On success: MFA marked as enrolled.
- ❌ On failure: Returns error (`Invalid code` or `MFA not enabled`).

---

### 🔓 `POST /mfa/disable`
- Disables and clears user's MFA setup.
- 🔒 Returns confirmation.

---

## 🧩 MFA Handling Scenarios

| 🧩 Scenario         | 🔎 Condition                                         | ✅ Action                                       |
|---------------------|------------------------------------------------------|-------------------------------------------------|
| ✅ New Setup         | No MFA enabled                                       | Proceed with requested MFA type                 |
| ❌ Already Enabled   | `enabled` + `enrolled` + different `mfa_type`        | Throw error                                     |
| 🔁 Incomplete Setup  | `disabled` + `pending` + different `mfa_type`        | Reset previous and allow new setup              |
| 🔐 TOTP              | `mfa_type === 'TOTP'`                                | Generate QR + base32 + store in DB              |
| 📧 Email             | `mfa_type === 'EMAIL'`                               | Send email + store token                        |
| 📵 SMS (Not Ready)   | `mfa_type === 'SMS'`                                 | Return not implemented message                  |
