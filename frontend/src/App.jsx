import { useState } from 'react'
import './App.css'

function App() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)

  const handleCheck = () => {
    // backend connection will go here later
    console.log('Checking URL:', url)
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
        />
        <button onClick={handleCheck}>Check URL</button>
      </div>

      <div className="result-area">
        {result === null ? (
          <p className="placeholder">Results will appear here</p>
        ) : (
          <div>
            <p>Score: {result.score}</p>
            <p>Level: {result.level}</p>
            <ul>
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
