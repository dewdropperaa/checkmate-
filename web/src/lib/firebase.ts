/**
 * Firebase client SDK init.
 *
 * All web config values below are public by design (Firebase Auth domain
 * restrictions / App Check / Security Rules protect the project — not secrecy).
 * Never put Admin SDK private keys or service-account JSON in NEXT_PUBLIC_* vars.
 *
 * IMPORTANT: Next.js only inlines NEXT_PUBLIC_* via *static* `process.env.FOO`
 * access. Dynamic `process.env[name]` stays undefined in the browser bundle.
 */
import { initializeApp, getApps, getApp, type FirebaseApp } from "firebase/app";
import { getAuth, type Auth } from "firebase/auth";

function requirePublicEnv(name: string, value: string | undefined): string {
  const trimmed = value?.trim();
  if (!trimmed) {
    throw new Error(
      `Missing ${name}. Copy web/.env.example to web/.env.local and fill Firebase web config.`,
    );
  }
  return trimmed;
}

function createFirebaseApp(): FirebaseApp {
  if (typeof window === "undefined") {
    throw new Error("Firebase Auth is only available in the browser");
  }
  if (getApps().length > 0) {
    return getApp();
  }
  // Validate required keys at first use (not at module load) so SSR/build
  // can import this file without crashing when env is absent in CI.
  const apiKey = requirePublicEnv(
    "NEXT_PUBLIC_FIREBASE_API_KEY",
    process.env.NEXT_PUBLIC_FIREBASE_API_KEY,
  );
  const authDomain = requirePublicEnv(
    "NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN",
    process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN,
  );
  const projectId = requirePublicEnv(
    "NEXT_PUBLIC_FIREBASE_PROJECT_ID",
    process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID,
  );
  const appId = requirePublicEnv(
    "NEXT_PUBLIC_FIREBASE_APP_ID",
    process.env.NEXT_PUBLIC_FIREBASE_APP_ID,
  );
  const messagingSenderId = requirePublicEnv(
    "NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID",
    process.env.NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID,
  );
  const storageBucket = process.env.NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET?.trim();
  const measurementId = process.env.NEXT_PUBLIC_FIREBASE_MEASUREMENT_ID?.trim();

  return initializeApp({
    apiKey,
    authDomain,
    projectId,
    appId,
    messagingSenderId,
    ...(storageBucket ? { storageBucket } : {}),
    ...(measurementId ? { measurementId } : {}),
  });
}

let _auth: Auth | null = null;

/** Lazily-initialized Auth instance for client components. */
export function getFirebaseAuth(): Auth {
  if (_auth) return _auth;
  _auth = getAuth(createFirebaseApp());
  return _auth;
}
