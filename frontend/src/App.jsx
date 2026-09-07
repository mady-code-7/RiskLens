import { useState, useRef, Component } from 'react'
import './App.css'

// Error boundaries must be class components — React has no hook
// equivalent. This catches any unexpected rendering crash (e.g. a
// future code change that mishandles a weird API response) so the
// visitor sees a recoverable message instead of a blank white page.
class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  componentDidCatch(error, info) {
    console.error('RiskLens crashed:', error, info)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="app">
          <div className="result-area">
            <div className="state state--error">
              <p className="error-message">
                Something went wrong. Please refresh the page and try again.
              </p>
            </div>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}

// Backend base URL. In production, set VITE_API_BASE_URL in your hosting
// provider's environment settings (e.g. Vercel/Netlify project settings)
// to your deployed FastAPI URL, such as https://risklens-api.onrender.com.
// Locally, Vite reads this from a .env file (see .env.example).
// Falls back to localhost so local dev keeps working with zero setup.
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

const LEVEL_CLASS = {
  Safe: 'level-safe',
  Suspicious: 'level-suspicious',
  Dangerous: 'level-dangerous',
}

// Real URLs are practically never this long. Rejecting early avoids
// sending huge payloads to the backend and keeps the UI responsive.
const MAX_URL_LENGTH = 2048

// Minimum time between checks. This is a courtesy speed bump for normal
// users double-clicking, not a security control — anyone can call the
// API directly and skip the frontend entirely. Real abuse protection
// (rate limiting) has to live on the backend.
const COOLDOWN_MS = 1500

// Rough client-side sanity check. The backend remains the source of truth
// for real validation — this just catches empty/obviously-broken input
// before spending a network round trip.
function looksLikeUrl(value) {
  if (!/\s/.test(value) && /\..+/.test(value)) return true
  try {
    new URL(value.includes('://') ? value : `http://${value}`)
    return true
  } catch {
    return false
  }
}

function RiskLensApp() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [isLoading, setIsLoading] = useState(false)
  const [isCoolingDown, setIsCoolingDown] = useState(false)
  const inputRef = useRef(null)
  const lastCheckAtRef = useRef(0)

  const handleCheck = async () => {
    const trimmedUrl = url.trim()

    if (!trimmedUrl) {
      setError('Enter a URL to check.')
      setResult(null)
      inputRef.current?.focus()
      return
    }

    if (trimmedUrl.length > MAX_URL_LENGTH) {
      setError(`That URL is too long (max ${MAX_URL_LENGTH} characters).`)
      setResult(null)
      inputRef.current?.focus()
      return
    }

    if (!looksLikeUrl(trimmedUrl)) {
      setError("That doesn't look like a valid URL. Try something like example.com.")
      setResult(null)
      inputRef.current?.focus()
      return
    }

    const now = Date.now()
    if (now - lastCheckAtRef.current < COOLDOWN_MS) {
      return
    }
    lastCheckAtRef.current = now

    setIsLoading(true)
    setError(null)
    setResult(null)

    // Abort if the backend hangs, so the button never gets stuck forever.
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 15000)

    try {
      const response = await fetch(`${API_BASE_URL}/check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: trimmedUrl }),
        signal: controller.signal,
      })

      if (!response.ok) {
        const errorBody = await response.json().catch(() => null)
        throw new Error(errorBody?.detail || `Request failed (${response.status})`)
      }

      const data = await response.json()

      if (
        typeof data?.score !== 'number' ||
        typeof data?.level !== 'string' ||
        !Array.isArray(data?.explanation)
      ) {
        throw new Error('Received an unexpected response from the server.')
      }

      setResult(data)
    } catch (err) {
      if (err.name === 'AbortError') {
        setError('The request took too long. Please try again.')
      } else if (err.message === 'Failed to fetch') {
        setError('Could not reach the RiskLens API. Please try again shortly.')
      } else {
        setError('Something went wrong. Please try again.')
      }
    } finally {
      clearTimeout(timeout)
      setIsLoading(false)
      setIsCoolingDown(true)
      setTimeout(() => setIsCoolingDown(false), COOLDOWN_MS)
    }
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !isLoading) {
      handleCheck()
    }
  }

  const scorePercent = result ? Math.min(100, Math.max(0, (result.score / 5) * 100)) : 0

  return (
    <div className="app">
      <div className="app__glow" aria-hidden="true" />

      <header className="header">
        <div className="brand">
          <span className="brand__mark" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path
                d="M12 2.5 4 5.75V11c0 5.14 3.4 9.55 8 10.9 4.6-1.35 8-5.76 8-10.9V5.75L12 2.5Z"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinejoin="round"
              />
              <path
                d="M9 12.2l2.1 2.1L15.5 10"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </span>
          <h1>RiskLens</h1>
        </div>
        <p className="subtitle">Paste a link. We'll tell you if it's safe to open.</p>
      </header>

      <main>
        <form
          className="check-form"
          onSubmit={(e) => {
            e.preventDefault()
            if (!isLoading) handleCheck()
          }}
        >
          <div className="input-row">
            <input
              ref={inputRef}
              type="text"
              inputMode="url"
              autoComplete="off"
              autoCapitalize="off"
              spellCheck="false"
              maxLength={MAX_URL_LENGTH}
              placeholder="e.g. secure-paypa1-login.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={handleKeyDown}
              aria-label="URL to check for phishing risk"
              aria-invalid={Boolean(error)}
              disabled={isLoading}
            />
            <button type="submit" disabled={isLoading || isCoolingDown}>
              {isLoading ? (
                <>
                  <span className="spinner" aria-hidden="true" />
                  Scanning
                </>
              ) : (
                'Check URL'
              )}
            </button>
          </div>
        </form>

        <div className="result-area" role="status" aria-live="polite">
          {error ? (
            <div className="state state--error">
              <p className="error-message">{error}</p>
            </div>
          ) : isLoading ? (
            <div className="state state--loading">
              <div className="scan-line" aria-hidden="true" />
              <p className="placeholder">Analyzing URL structure and signals&hellip;</p>
            </div>
          ) : result === null ? (
            <div className="state state--empty">
              <p className="placeholder">Results will appear here</p>
            </div>
          ) : (
            <div className={`result ${LEVEL_CLASS[result.level] || ''}`}>
              <div className="result-header">
                <div className="meter" aria-hidden="true">
                  <svg viewBox="0 0 120 68" className="meter__svg">
                    <path
                      d="M10 60 A50 50 0 0 1 110 60"
                      className="meter__track"
                      fill="none"
                    />
                    <path
                      d="M10 60 A50 50 0 0 1 110 60"
                      className="meter__fill"
                      fill="none"
                      style={{
                        strokeDasharray: 157,
                        strokeDashoffset: 157 - (157 * scorePercent) / 100,
                      }}
                    />
                  </svg>
                  <div className="meter__value">
                    <span className="score">{result.score}</span>
                    <span className="score__max">/5</span>
                  </div>
                </div>
                <span className="level">{result.level}</span>
              </div>

              <ul className="explanation-list">
                {result.explanation.map((reason, i) => (
                  <li key={i}>
                    <span className="explanation-dot" aria-hidden="true" />
                    {reason}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </main>

      <footer className="footer">
        <p>RiskLens flags patterns common in phishing URLs. Always use your own judgment.</p>
      </footer>
    </div>
  )
}

function App() {
  return (
    <ErrorBoundary>
      <RiskLensApp />
    </ErrorBoundary>
  )
}

export default App
