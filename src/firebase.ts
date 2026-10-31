import { getApp, getApps, initializeApp } from 'firebase/app'
import { getAuth, type Auth } from 'firebase/auth'
import { getFirestore, type Firestore } from 'firebase/firestore'

const config = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY as string | undefined,
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN as string | undefined,
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID as string | undefined,
  appId: import.meta.env.VITE_FIREBASE_APP_ID as string | undefined,
}

export const firebaseConfigured = Boolean(config.apiKey && config.authDomain && config.projectId && config.appId)
let authInstance: Auth | null = null
let firestoreInstance: Firestore | null = null

if (firebaseConfigured) {
  const app = getApps().length ? getApp() : initializeApp(config)
  authInstance = getAuth(app)
  firestoreInstance = getFirestore(app)
}

export const auth = authInstance
export const db = firestoreInstance
