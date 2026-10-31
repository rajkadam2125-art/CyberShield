# CyberShield

CyberShield is a cybersecurity-awareness web application built with React, TypeScript, Vite, Express, Firebase Authentication, and Cloud Firestore.

## Retained features

- Email validation through ZeroBounce when a valid server-side API key is configured.
- Domain reputation lookup through VirusTotal when a valid server-side API key is configured.
- Local password-strength heuristic. Passwords are never sent to external APIs or saved in scan history.
- Device security guidance checklist. This is not a device scan.
- Wi-Fi safety guidance checklist. This is not a live network scan.
- Cybersecurity Assistant: uses xAI Grok when configured; otherwise uses a local ruleset.
- Per-user scan history saved in Firestore.

The **App Security** and **File Vault** features have been removed.

## Requirements

- Node.js 20 or newer (Node.js 22 recommended).
- A Firebase project.
- Firebase Authentication with Email/Password enabled.
- Cloud Firestore created.
- Optional VirusTotal, ZeroBounce, and xAI Grok API keys.

## 1. Install dependencies

Open a terminal in this folder:

```bash
npm install
```

## 2. Configure Firebase web app

In the Firebase Console, create/select your project and register a Web App. Enable **Authentication → Sign-in method → Email/Password** and create a Firestore database.

Copy `.env.example` to `.env`, then fill in the public web configuration values:

```env
VITE_FIREBASE_API_KEY=...
VITE_FIREBASE_AUTH_DOMAIN=your-project.firebaseapp.com
VITE_FIREBASE_PROJECT_ID=your-project-id
VITE_FIREBASE_APP_ID=...
```

These web configuration values are intended for the browser. Firestore Security Rules still protect the data.

## 3. Configure backend Firebase Admin credentials

The backend must verify Firebase ID tokens and use the Admin SDK to write scan records.

For local development:

1. In Firebase Console → Project Settings → Service accounts, create/download a private service-account JSON file.
2. Place it in this project root as `firebase-service-account.json`.
3. Never commit or share that file.
4. In `.env`, set:

```env
FIREBASE_PROJECT_ID=your-project-id
GOOGLE_APPLICATION_CREDENTIALS=./firebase-service-account.json
CLIENT_ORIGIN=http://localhost:5173
PORT=4000
```

Alternatively, configure Application Default Credentials in your environment or use `FIREBASE_SERVICE_ACCOUNT_JSON` in a secure server environment. Do not place service-account credentials in any `VITE_` variable.

## 4. Configure external API keys

In `.env`, set:

```env
VIRUSTOTAL_API_KEY=your_virustotal_key
ZEROBOUNCE_API_KEY=your_zerobounce_key
XAI_API_KEY=your_xai_api_key
XAI_MODEL=grok-4.7
```

- VirusTotal official API documentation: https://docs.virustotal.com/reference/overview
- ZeroBounce official API documentation: https://www.zerobounce.net/docs/
- xAI Grok Responses API documentation: https://docs.x.ai/developers/rest-api-reference/inference/responses

These keys must stay on the backend. Do not paste them into frontend code or commit `.env`.

If a key is missing or the provider fails, the application reports that the result is unavailable. It does not invent a successful scan.

## 5. Deploy Firestore rules and indexes

Install Firebase CLI if needed, sign in, and select the project:

```bash
npm install -g firebase-tools
firebase login
firebase use --add
firebase deploy --only firestore:rules,firestore:indexes
```

Confirm the selected project before deployment. Review the rules before using any production data.

The frontend creates the user's profile document after signup. The Express backend writes scan history with Firebase Admin SDK. Admin SDK bypasses Firestore Rules, so the backend verifies each ID token and uses the verified UID to scope every scan query.

## 6. Run the application

Start the frontend and backend together:

```bash
npm run dev
```

Open:

- Frontend: http://localhost:5173
- Backend health: http://localhost:4000/api/health

The health endpoint reports whether Firebase Admin, Firestore, VirusTotal, ZeroBounce, and xAI are configured. It does not prove that external API credentials are valid; run a controlled check to verify each provider.

## 7. Build

```bash
npm run build
npm run server:build
npm run test
```

The production backend entry point is `dist-server/index.js`. Configure production environment variables and a secure credential mechanism before deploying.

## API overview

| Method | Endpoint | Authentication | Purpose |
|---|---|---|---|
| GET | `/api/health` | Public | Configuration status |
| GET | `/api/summary` | Firebase ID token | Current user's dashboard summary |
| GET | `/api/scans` | Firebase ID token | Current user's scan history |
| POST | `/api/check` | Firebase ID token | Run a check and save its result |
| DELETE | `/api/scans` | Firebase ID token | Delete the current user's scan history |

Protected routes require `Authorization: Bearer <Firebase ID token>`.

## Result interpretation and limitations

- **VirusTotal:** reports the provider's domain analysis. No detections does not guarantee a site is safe. This checks the hostname, not every page or redirect.
- **ZeroBounce:** reports the provider's email validation status. A valid address does not prove the sender is trustworthy.
- **Password Check:** uses a local heuristic and does not perform a breach lookup.
- **Device and Wi-Fi checks:** provide guidance only. A browser cannot reliably inspect all device settings or current Wi-Fi encryption.
- **Cybersecurity Guidance:** uses a local ruleset, not Grok or another AI API.

## Troubleshooting

- **Firebase client setup message:** check the `VITE_FIREBASE_*` variables and restart Vite after changing `.env`.
- **Backend says Firebase Admin is not configured:** check `GOOGLE_APPLICATION_CREDENTIALS`, `FIREBASE_PROJECT_ID`, and the service-account file path.
- **Firestore permission/index error:** deploy `firestore.rules` and `firestore.indexes.json` to the correct Firebase project.
- **VirusTotal/ZeroBounce unavailable:** verify the server-side API key, quota, provider status, and network connectivity.
- **Login works but dashboard APIs return 401:** verify that the frontend Firebase project and backend Admin project are the same project.
- **Never use open Firestore rules as a workaround.**

## Verification status

The source archive provided for this work did not include installed `node_modules`, Firebase project credentials, or the two external API keys. Therefore, a successful production build and real external API responses must be verified in the configured environment. Do not treat missing-credential responses as a successful scan.
