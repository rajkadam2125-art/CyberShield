import { useState, type FormEvent } from 'react'
import { createUserWithEmailAndPassword, sendPasswordResetEmail, signInWithEmailAndPassword, updateProfile } from 'firebase/auth'
import { doc, serverTimestamp, setDoc } from 'firebase/firestore'
import { ShieldCheck, Eye, EyeOff, LoaderCircle } from 'lucide-react'
import { auth, db, firebaseConfigured } from './firebase'

type Props = { onAuthenticated: () => void }

function friendlyError(error: unknown): string {
  const code = (error as { code?: string })?.code || ''
  const messages: Record<string, string> = {
    'auth/invalid-credential': 'Email or password is incorrect.',
    'auth/invalid-email': 'Enter a valid email address.',
    'auth/email-already-in-use': 'An account already exists with this email.',
    'auth/weak-password': 'Choose a stronger password (at least 6 characters).',
    'auth/too-many-requests': 'Too many attempts. Please wait and try again.',
    'auth/network-request-failed': 'Network error. Check your internet connection.',
    'auth/user-not-found': 'No account was found for this email.',
    'auth/wrong-password': 'Email or password is incorrect.',
  }
  return messages[code] || 'Authentication could not be completed. Check Firebase configuration and try again.'
}

export default function AuthScreen({ onAuthenticated }: Props) {
  const [mode, setMode] = useState<'login' | 'signup'>('login')
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError('')
    setMessage('')
    if (!firebaseConfigured || !auth || !db) {
      setError('Firebase is not configured yet. Add the VITE_FIREBASE_* values to your .env file, then restart the dev server.')
      return
    }
    if (!email.trim() || !password) { setError('Enter your email and password.'); return }
    if (mode === 'signup' && name.trim().length < 2) { setError('Enter your full name (at least 2 characters).'); return }
    if (mode === 'signup' && password.length < 8) { setError('Use a password with at least 8 characters.'); return }
    if (mode === 'signup' && password !== confirmPassword) { setError('Password and confirm password do not match.'); return }
    setBusy(true)
    try {
      if (mode === 'signup') {
        const credential = await createUserWithEmailAndPassword(auth, email.trim().toLowerCase(), password)
        await updateProfile(credential.user, { displayName: name.trim() })
        await setDoc(doc(db, 'users', credential.user.uid), {
          uid: credential.user.uid,
          fullName: name.trim(),
          email: credential.user.email,
          role: 'user',
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
        })
      } else {
        await signInWithEmailAndPassword(auth, email.trim().toLowerCase(), password)
      }
      onAuthenticated()
    } catch (e) {
      setError(friendlyError(e))
    } finally {
      setBusy(false)
    }
  }

  async function resetPassword() {
    setError('')
    setMessage('')
    if (!firebaseConfigured || !auth) { setError('Configure Firebase before using password reset.'); return }
    if (!email.trim()) { setError('Enter your email address first.'); return }
    setBusy(true)
    try {
      await sendPasswordResetEmail(auth, email.trim().toLowerCase())
      setMessage('If the account is registered, Firebase will send a password-reset email.')
    } catch { setError('Password reset could not be requested. Check the email address and Firebase configuration.') }
    finally { setBusy(false) }
  }

  return <main className="auth-screen">
    <section className="auth-brand-panel">
      <div className="auth-brand"><div className="brand-mark"><ShieldCheck size={24}/></div><div><strong>CyberShield</strong><span>SECURITY CENTER</span></div></div>
      <div className="auth-hero">
        <div className="auth-eyebrow">CYBERSECURITY</div>
        <h1>Make safer<br/><span>digital decisions.</span></h1>
        <p>Review domain reputation, validate email addresses, and get practical security guidance from one workspace.</p>
        <div className="auth-trust"><ShieldCheck size={17}/> Protected sign-in powered by Firebase Authentication</div>
      </div>
      <div className="auth-brand-footer">CyberShield · Project</div>
    </section>
    <section className="auth-form-panel">
      <form className="auth-card" onSubmit={submit}>
        <div className="auth-mobile-brand"><ShieldCheck size={24}/> CyberShield</div>
        <div className="eyebrow">{mode === 'login' ? 'WELCOME BACK' : 'GET STARTED'}</div>
        <h2>{mode === 'login' ? 'Sign in to your account' : 'Create your account'}</h2>
        <p className="auth-subtitle">{mode === 'login' ? 'Sign in to access your personal security workspace.' : 'Create an account to save your security scan history.'}</p>
        {!firebaseConfigured && <div className="auth-config-note"><strong>Setup required</strong><p>Firebase client configuration is missing. Add the required VITE_FIREBASE_* values to the project .env file and restart Vite.</p></div>}
        {mode === 'signup' && <label className="auth-label">Full name<input autoComplete="name" value={name} onChange={e=>setName(e.target.value)} placeholder="Your full name" disabled={busy}/></label>}
        <label className="auth-label">Email address<input autoComplete="email" type="email" value={email} onChange={e=>setEmail(e.target.value)} placeholder="you@example.com" disabled={busy}/></label>
        <label className="auth-label">Password<span className="auth-password-wrap"><input autoComplete={mode==='login'?'current-password':'new-password'} type={showPassword?'text':'password'} value={password} onChange={e=>setPassword(e.target.value)} placeholder={mode==='login'?'Enter your password':'At least 8 characters'} disabled={busy}/><button type="button" className="password-toggle" aria-label={showPassword?'Hide password':'Show password'} onClick={()=>setShowPassword(!showPassword)}>{showPassword?<EyeOff size={17}/>:<Eye size={17}/>}</button></span></label>
        {mode === 'signup' && <label className="auth-label">Confirm password<input autoComplete="new-password" type="password" value={confirmPassword} onChange={e=>setConfirmPassword(e.target.value)} placeholder="Re-enter your password" disabled={busy}/></label>}
        {mode === 'login' && <button type="button" className="forgot-link" onClick={()=>void resetPassword()} disabled={busy}>Forgot password?</button>}
        {error && <div className="auth-message auth-error" role="alert">{error}</div>}
        {message && <div className="auth-message auth-success" role="status">{message}</div>}
        <button className="auth-submit" type="submit" disabled={busy}>{busy?<><LoaderCircle size={17} className="spin"/> Please wait…</>:mode==='login'?'Sign in':'Create account'}</button>
        <p className="auth-switch">{mode==='login'?"Don't have an account?":'Already have an account?'} <button type="button" onClick={()=>{setMode(mode==='login'?'signup':'login');setError('');setMessage('')}} disabled={busy}>{mode==='login'?'Create account':'Sign in'}</button></p>
        <p className="auth-privacy">Your password is handled by Firebase Authentication and is never stored in the CyberShield Firestore profile.</p>
      </form>
    </section>
  </main>
}
