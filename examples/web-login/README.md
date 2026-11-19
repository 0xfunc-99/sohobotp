# Example: a website that asks for a SohobOTP code

`index.php` is a small "Demo Cloud Console" that signs people in with **password + SohobOTP
code**, using the portal's REST API. It shows, under each page, the API calls it made
(the key and the codes are hidden), so you can copy the pattern into your own application.

## How an application uses SohobOTP

1. The application checks the user's **own password** as it always did.
2. It asks for the 6-digit code and sends it to the portal:

   ```sh
   curl -s -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
        -d '{"user":"alice","code":"123456"}' https://PORTAL/portal/api.php/v1/auth/check
   ```

   Answer: `{"user":"alice","result":"accepted"}`. Only `accepted` lets the user in; the
   others are `rejected` (wrong code), `locked` (too many wrong codes), `disabled`, `unknown`.
   The portal counts wrong codes and locks the user like any other sign-in; each check is in
   the audit trail (`api.auth_check`).
3. Optional: `GET /v1/users?q=&per_page=` lists users (name, state, authenticator), for an
   admin page or to match the application's accounts.

The API key comes from the portal (**API keys**, super administrator): give it only the
permissions the application needs (`Check a user's code`, and `Read users` for the list),
limit it to the application server's address, and keep it on the server (never in a browser).

## Run the demo

```sh
docker run -d --name sohobotp-demo --user 33:33 -p 127.0.0.1:8090:8090 \
  -v "$PWD/examples/web-login":/app:ro -v sohobotp-demo-data:/data \
  -e SOHOBOTP_PORTAL=https://PORTAL -e SOHOBOTP_CA=/data/portal-ca.pem \
  -e SOHOBOTP_API_KEY_FILE=/data/api-key -e DEMO_PASSWORD=demo \
  multiotp-portal-php php -S 0.0.0.0:8090 -t /app
```

Open http://127.0.0.1:8090, paste the API key once, then sign in with a SohobOTP user name,
the demo password and the user's code. `SOHOBOTP_CA` is the portal's CA certificate when it
is not publicly trusted (`SOHOBOTP_INSECURE=1` switches the check off: a throwaway test only).

## Protecting a real application

- **It can call an API** (your own code, a login plugin): do as above.
- **It supports RADIUS for its second factor** (many VPNs, VMware Horizon, network devices):
  add it under *VPNs and devices* instead; nothing to program.
- **It has no login of its own, or none you can change** (Prometheus, Alertmanager, many
  dashboards): put a login gateway in front of it that asks for the code, then lets the
  request through (nginx `auth_request` to a small page like this one).
