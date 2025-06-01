import React, { useState, useEffect } from "react";
import "./App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Lock, Eye, Users, Zap, Upload, Target, Timer, Play } from "lucide-react";

// Components
import LandingPage from "./components";
import WhispererOnboarding from "./components";
import VaultCreation from "./components";

// API Configuration
const API_BASE_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

// API Helper Functions
const apiCall = async (endpoint, options = {}) => {
  const token = localStorage.getItem('authToken');
  const headers = {
    'Content-Type': 'application/json',
    ...(token && { 'Authorization': `Bearer ${token}` }),
    ...options.headers
  };

  try {
    // Use the correct API endpoint - if we're in production, use /api prefix
    const apiUrl = API_BASE_URL.includes('preview.emergentagent.com') 
      ? `${API_BASE_URL}/api${endpoint}`
      : `${API_BASE_URL}/api${endpoint}`;
    
    console.log('Making API call to:', apiUrl);
    
    const response = await fetch(apiUrl, {
      ...options,
      headers
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    return data;
  } catch (error) {
    console.error('API call error:', error);
    throw error;
  }
};

function App() {
  const [currentView, setCurrentView] = useState('landing'); // landing, onboarding, vault-creation
  const [user, setUser] = useState(null);
  const [vaults, setVaults] = useState([]); // Initialize as empty array
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Load user from localStorage on app start
  useEffect(() => {
    const token = localStorage.getItem('authToken');
    const userData = localStorage.getItem('userData');
    
    if (token && userData) {
      try {
        setUser(JSON.parse(userData));
      } catch (e) {
        localStorage.removeItem('authToken');
        localStorage.removeItem('userData');
      }
    }
    
    loadVaults();
  }, []);

  const loadVaults = async () => {
    try {
      setLoading(true);
      const response = await apiCall('/vaults?limit=20');
      if (response.success) {
        setVaults(response.data);
      }
    } catch (error) {
      console.error('Failed to load vaults:', error);
      setError('Failed to load vaults');
    } finally {
      setLoading(false);
    }
  };

  const handleNavigation = (view, data = null) => {
    setCurrentView(view);
    if (data) {
      if (data.user) {
        setUser(data.user);
        localStorage.setItem('userData', JSON.stringify(data.user));
      }
      if (data.token) {
        localStorage.setItem('authToken', data.token);
      }
      if (data.vault) {
        loadVaults(); // Reload vaults to get updated data
      }
    }
  };

  return (
    <div className="App">
      <BrowserRouter>
        <Routes>
          <Route path="/" element={
            <div className="min-h-screen bg-gradient-to-br from-slate-950 via-blue-950 to-purple-950">
              <AnimatePresence mode="wait">
                {currentView === 'landing' && (
                  <LandingPage 
                    key="landing"
                    onNavigate={handleNavigation}
                    vaults={vaults}
                    loading={loading}
                    error={error}
                    user={user}
                    apiCall={apiCall}
                  />
                )}
                {currentView === 'onboarding' && (
                  <WhispererOnboarding 
                    key="onboarding"
                    onNavigate={handleNavigation}
                    onComplete={(userData) => handleNavigation('vault-creation', userData)}
                    apiCall={apiCall}
                  />
                )}
                {currentView === 'vault-creation' && (
                  <VaultCreation 
                    key="vault-creation"
                    onNavigate={handleNavigation}
                    user={user}
                    onVaultCreated={(vault) => handleNavigation('landing', { vault })}
                    apiCall={apiCall}
                  />
                )}
              </AnimatePresence>
            </div>
          } />
        </Routes>
      </BrowserRouter>
    </div>
  );
}

export default App;