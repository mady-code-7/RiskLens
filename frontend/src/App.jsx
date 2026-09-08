import { useState, useRef, useEffect, Component } from 'react'
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
                Too many requests. Please try again later.
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

// Free-tier hosts (e.g. Render) spin the backend down after inactivity,
// and waking it back up can take well past a normal request's timeout.
// FIRST_ATTEMPT_TIMEOUT_MS covers a warm backend. If that attempt times
// out, we assume the server is asleep, retry once with a much longer
// window, and show a "waking up" message instead of an error so a cold
// start doesn't look like a failure.
const FIRST_ATTEMPT_TIMEOUT_MS = 8000
const RETRY_TIMEOUT_MS = 45000

// If the first attempt is still running after this long, the backend is
// probably waking up rather than just being slow — switch the loading
// copy to say so.
const SLOW_RESPONSE_HINT_MS = 4000

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
  const [isWaking, setIsWaking] = useState(false)
  const [showSlowHint, setShowSlowHint] = useState(false)
  const inputRef = useRef(null)
  const lastCheckAtRef = useRef(0)

  // During the first attempt, if it's taking a while, hint that the
  // server might be waking up rather than leaving a bare spinner —
  // avoids it looking frozen before the retry logic even kicks in.
  useEffect(() => {
    if (!isLoading || isWaking) {
      setShowSlowHint(false)
      return
    }
    const timer = setTimeout(() => setShowSlowHint(true), SLOW_RESPONSE_HINT_MS)
    return () => clearTimeout(timer)
  }, [isLoading, isWaking])

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
    setIsWaking(false)
    setError(null)
    setResult(null)

    try {
      // First attempt: assumes a warm backend. Short timeout so a genuinely
      // sleeping server fails fast and we can move on to the retry rather
      // than making the user wait through two long timeouts back to back.
      const data = await attemptCheck(trimmedUrl, FIRST_ATTEMPT_TIMEOUT_MS)
      setResult(data)
    } catch (firstErr) {
      if (firstErr.name !== 'AbortError') {
        // Not a timeout — a real error (bad response, network failure, etc).
        // Retrying won't help, so surface it immediately.
        setError(describeError(firstErr))
        clearLoadingState()
        return
      }

      // Timed out on the first try — likely a cold start on a free-tier
      // host. Retry once with a much longer window, and let the user know
      // the server is waking up rather than just showing a spinner.
      setIsWaking(true)
      try {
        const data = await attemptCheck(trimmedUrl, RETRY_TIMEOUT_MS)
        setResult(data)
      } catch (secondErr) {
        setError(describeError(secondErr))
      }
    } finally {
      clearLoadingState()
    }
  }

  // Runs one fetch attempt against the backend with the given timeout.
  // Throws on non-OK responses, malformed payloads, network failure, or
  // abort (timeout) — callers decide how to react to each.
  const attemptCheck = async (trimmedUrl, timeoutMs) => {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), timeoutMs)

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

      return data
    } finally {
      clearTimeout(timeout)
    }
  }

  const describeError = (err) => {
    if (err.name === 'AbortError') {
      return "The server is taking longer than expected to wake up. Please try again in a moment."
    }
    if (err.message === 'Failed to fetch') {
      return 'Could not reach the RiskLens API. Please try again shortly.'
    }
    return 'Take a break. Please try again later.'
  }

  const clearLoadingState = () => {
    setIsLoading(false)
    setIsWaking(false)
    setIsCoolingDown(true)
    setTimeout(() => setIsCoolingDown(false), COOLDOWN_MS)
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
              {isWaking ? (
                <p className="placeholder placeholder--waking">
                  Waking up the server&hellip; this can take up to a minute on the first check.
                </p>
              ) : showSlowHint ? (
                <p className="placeholder placeholder--waking">
                  Still working&hellip; the server may be starting up.
                </p>
              ) : (
                <p className="placeholder">Analyzing URL structure and signals&hellip;</p>
              )}
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
