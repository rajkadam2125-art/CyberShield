import { FieldValue, firestore } from './firebase.js'

export type ScanRecord = {
  id: string
  userId: string
  type: string
  inputPreview: string
  status: 'complete' | 'unavailable'
  summary: string
  createdAt: string
  details: Record<string, unknown>
}

function requireDb() {
  if (!firestore) throw new Error('FIRESTORE_NOT_CONFIGURED')
  return firestore
}

export async function getScans(userId: string): Promise<ScanRecord[]> {
  const db = requireDb()
  const snapshot = await db.collection('scan_history')
    .where('userId', '==', userId)
    .orderBy('createdAt', 'desc')
    .limit(300)
    .get()
  return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() } as ScanRecord))
}

export async function addScan(record: ScanRecord): Promise<ScanRecord> {
  const db = requireDb()
  const { id, ...data } = record
  await db.collection('scan_history').doc(id).set({
    ...data,
    createdAtServer: FieldValue.serverTimestamp(),
  })
  return record
}

export async function clearScans(userId: string): Promise<void> {
  const db = requireDb()
  const snapshot = await db.collection('scan_history').where('userId', '==', userId).get()
  for (let start = 0; start < snapshot.docs.length; start += 450) {
    const batch = db.batch()
    snapshot.docs.slice(start, start + 450).forEach(doc => batch.delete(doc.ref))
    await batch.commit()
  }
}
