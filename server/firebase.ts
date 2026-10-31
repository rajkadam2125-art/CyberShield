import { applicationDefault, cert, initializeApp, type App } from 'firebase-admin/app'
import { getAuth } from 'firebase-admin/auth'
import { FieldValue, getFirestore } from 'firebase-admin/firestore'

let adminApp: App | null = null

try {
  if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON)
    adminApp = initializeApp({
      credential: cert(serviceAccount),
      projectId: process.env.FIREBASE_PROJECT_ID || serviceAccount.project_id,
    })
  } else if (process.env.GOOGLE_APPLICATION_CREDENTIALS || process.env.FIREBASE_USE_ADC === 'true') {
    adminApp = initializeApp({
      credential: applicationDefault(),
      ...(process.env.FIREBASE_PROJECT_ID ? { projectId: process.env.FIREBASE_PROJECT_ID } : {}),
    })
  }
} catch (error) {
  console.error('Firebase Admin initialization failed. Check server Firebase configuration.')
}

export const firebaseAdminConfigured = Boolean(adminApp)
export const adminAuth = adminApp ? getAuth(adminApp) : null
export const firestore = adminApp ? getFirestore(adminApp) : null
export { FieldValue }
