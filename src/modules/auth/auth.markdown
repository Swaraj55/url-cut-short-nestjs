| 🧾 Case                                        | ⚙️ Condition                              | 🤖 Behavior                      | 💬 Response Message                                                          |
|-----------------------------------------------|-------------------------------------------|----------------------------------|------------------------------------------------------------------------------|
| ❌ MFA not enabled                             | `!mfa` or `mfa.mfa_status !== 'enabled'`  | 🔓 Logs in directly              | 🔑 Returns access & refresh tokens                                          |
| 🔐 MFA enabled, not enrolled, no code         | `mfa_state === 'unenrolled' && !mfaCode`  | 🏁 Starts enrollment             | 🧩 TOTP: QR code & secret<br>📧 Email: sends verification code               |
| 🔐 MFA enabled, not enrolled, with code       | `mfa_state === 'unenrolled' && mfaCode`   | ✅ Verifies first MFA code       | 📥 Marks as enrolled, prompts re-login                                      |
| 🟡 MFA enrolled, no code                      | `mfa_state === 'enrolled' && !mfaCode`    | 🔁 Sends MFA code if Email       | ⌨️ Asks user to provide MFA code                                             |
| 🟢 MFA enrolled, with code                    | `mfa_state === 'enrolled' && mfaCode`     | 🟩 Verifies and logs in          | 🪪 Returns access & refresh tokens                                          |
| 🧯 Unexpected MFA state                       | Anything outside expected combinations     | 🛑 Fails safe                     | ⚠️ Throws: "Unexpected MFA state. Please try again."                         |


## 🔐 Cookie Security Measures

**1. 🛡️ Prevent JavaScript Access (XSS Protection)**  
`httpOnly: true` ensures the cookie **cannot be accessed via `document.cookie`** in JavaScript, preventing **cross-site scripting (XSS)** attacks from stealing tokens stored in the browser.

---

**2. 🔒 Enforce Secure Transmission (HTTPS Only)**  
`secure: true` ensures cookies are **only sent over HTTPS connections**, preventing **man-in-the-middle (MITM)** attacks that try to intercept cookies on non-secure HTTP.

---

**3. 🧷 Prevent CSRF Attacks**  
`sameSite: 'strict'` ensures cookies are **not sent on cross-origin requests**, blocking **cross-site request forgery (CSRF)** attacks where attackers trick the browser into sending authenticated requests.

---

**4. ⏳ Persistent Yet Controlled Session**  
`maxAge: <time_in_milliseconds>` sets the cookie's **lifetime** (e.g., `maxAge: 604800000` for 7 days), allowing the user to **stay logged in securely across browser sessions** while still allowing expiration.

---

**5. 🔄 Automatic Inclusion with Requests**  
Cookies are **automatically included** in HTTP requests to the server (same origin), eliminating the need to **manually attach refresh tokens** in API requests and simplifying frontend logic.
