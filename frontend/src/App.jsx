import { useState } from 'react'
import './App.css'

// The backend's base URL. During local development this points at the
// FastAPI dev server. When deployed, update this to the deployed
// backend URL (e.g. https://risklens-api.onrender.com).
const API_BASE_URL = 'http://localhost:8000'

// Maps a risk level to a CSS class so the result area can be styled
// differently (e.g. colors) depending on Safe / Suspicious / Dangerous.
const LEVEL_CLASS = {
  Safe: 'level-safe',
  Suspicious: 'level-suspicious',
  Dangerous: 'level-dangerous',
}

function App() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [isLoading, setIsLoading] = useState(false)

  const handleCheck = async () => {
    const trimmedUrl = url.trim()
    if (!trimmedUrl) {
      setError('Please enter a URL to check.')
      setResult(null)
      return
    }

    setIsLoading(true)
    setError(null)
    setResult(null)

    try {
      const response = await fetch(`${API_BASE_URL}/check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: trimmedUrl }),
      })

      if (!response.ok) {
        const errorBody = await response.json().catch(() => null)
        throw new Error(errorBody?.detail || `Request failed (${response.status})`)
      }

      const data = await response.json()
      setResult(data)
    } catch (err) {
      setError(
        err.message === 'Failed to fetch'
          ? 'Could not reach the RiskLens API. Is the backend running?'
          : err.message
      )
    } finally {
      setIsLoading(false)
    }
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !isLoading) {
      handleCheck()
    }
  }

  return (
    <div className="app">
      <h1>RiskLens</h1>
      <p className="subtitle">Check a URL for phishing risk</p>

      <div className="input-row">
        <input
          type="text"
          placeholder="Enter a URL..."
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={handleKeyDown}
        />
        <button onClick={handleCheck} disabled={isLoading}>
          {isLoading ? 'Checking...' : 'Check URL'}
        </button>
      </div>

      <div className="result-area">
        {error ? (
          <p className="error-message">{error}</p>
        ) : result === null ? (
          <p className="placeholder">Results will appear here</p>
        ) : (
          <div className={`result ${LEVEL_CLASS[result.level] || ''}`}>
            <div className="result-header">
              <span className="score">{result.score} / 5</span>
              <span className="level">{result.level}</span>
            </div>
            <ul className="explanation-list">
              {result.explanation.map((reason, i) => (
                <li key={i}>{reason}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  )
}

export default App
