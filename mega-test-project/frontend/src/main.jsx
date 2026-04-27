// =============================================================================
// frontend/src/main.jsx – React App Entry Point
// =============================================================================
// PURPOSE: This file boots up the React application.
//
// ⚠️  INTENTIONAL ISSUES:
//   1. BAD: No error boundary at the root level — a crash kills the whole app
//   2. BAD: StrictMode removed (commented out) — hides potential issues during dev
// =============================================================================

import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'

// BAD: React.StrictMode should be wrapping App — it helps catch bugs
// It was removed because "it causes double renders" — that is the point!
ReactDOM.createRoot(document.getElementById('root')).render(
    // <React.StrictMode>
    <App />
    // </React.StrictMode>
)
