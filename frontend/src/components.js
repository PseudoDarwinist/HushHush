import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Lock, Eye, Users, Zap, Upload, Target, Timer, Play, ArrowRight, Shield, Mic, DollarSign, Clock, Share2, CheckCircle, AlertCircle, LogOut } from "lucide-react";

// Landing Page Component
const LandingPage = ({ onNavigate, vaults, loading, error, user, apiCall }) => {
  const [selectedVault, setSelectedVault] = useState(null);
  const [showLogin, setShowLogin] = useState(false);

  const handleLogout = () => {
    localStorage.removeItem('authToken');
    localStorage.removeItem('userData');
    window.location.reload();
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="min-h-screen text-white relative overflow-hidden"
    >
      {/* Background Effects */}
      <div className="absolute inset-0 bg-gradient-to-br from-slate-950 via-blue-950 to-purple-950"></div>
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_20%,rgba(59,130,246,0.15),transparent)] blur-xl"></div>
      
      {/* Navigation */}
      <nav className="relative z-10 flex justify-between items-center p-6">
        <div className="flex items-center space-x-2">
          <div className="w-8 h-8 bg-gradient-to-r from-cyan-400 to-purple-500 rounded-full flex items-center justify-center">
            <Lock className="w-4 h-4 text-white" />
          </div>
          <span className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
            HushHush
          </span>
        </div>
        <div className="flex space-x-4 items-center">
          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            className="px-4 py-2 text-gray-300 hover:text-white transition-colors"
          >
            Explore
          </motion.button>
          {user ? (
            <div className="flex items-center space-x-4">
              <span className="text-gray-300">Welcome, {user.username}</span>
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={handleLogout}
                className="px-4 py-2 bg-gradient-to-r from-red-600 to-red-700 rounded-full text-white font-medium shadow-lg flex items-center space-x-2"
              >
                <LogOut className="w-4 h-4" />
                <span>Logout</span>
              </motion.button>
            </div>
          ) : (
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={() => setShowLogin(true)}
              className="px-6 py-2 bg-gradient-to-r from-cyan-600 to-purple-600 rounded-full text-white font-medium shadow-lg shadow-purple-500/25"
            >
              Sign In
            </motion.button>
          )}
        </div>
      </nav>

      {/* Hero Section */}
      <div className="relative z-10 max-w-6xl mx-auto px-6 pt-20 pb-32">
        <motion.div
          initial={{ y: 50, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.2, duration: 0.8 }}
          className="text-center mb-16"
        >
          <h1 className="text-6xl md:text-8xl font-bold mb-6">
            <span className="bg-gradient-to-r from-cyan-400 via-purple-400 to-pink-400 bg-clip-text text-transparent">
              Your Secrets
            </span>
            <br />
            <span className="text-white">Have Value</span>
          </h1>
          <p className="text-xl text-gray-300 max-w-3xl mx-auto mb-12 leading-relaxed">
            Transform your untold stories into income. Share secrets anonymously, 
            let listeners fund the reveal. The bigger the secret, the bigger the reward.
          </p>
          
          {/* Action Buttons */}
          <div className="flex flex-col sm:flex-row gap-6 justify-center items-center">
            <motion.button
              whileHover={{ scale: 1.05, boxShadow: "0 20px 40px rgba(34, 197, 94, 0.4)" }}
              whileTap={{ scale: 0.95 }}
              onClick={() => user ? onNavigate('vault-creation') : setShowLogin(true)}
              className="group px-8 py-4 bg-gradient-to-r from-emerald-500 to-teal-500 rounded-full text-white font-semibold text-lg shadow-lg shadow-emerald-500/25 flex items-center space-x-2"
            >
              <Mic className="w-5 h-5" />
              <span>Become a Whisperer</span>
              <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
            </motion.button>
            
            <motion.button
              whileHover={{ scale: 1.05, boxShadow: "0 20px 40px rgba(168, 85, 247, 0.4)" }}
              whileTap={{ scale: 0.95 }}
              className="group px-8 py-4 bg-gradient-to-r from-purple-600 to-pink-600 rounded-full text-white font-semibold text-lg shadow-lg shadow-purple-500/25 flex items-center space-x-2"
            >
              <Eye className="w-5 h-5" />
              <span>Fund Secrets</span>
              <DollarSign className="w-5 h-5 group-hover:scale-110 transition-transform" />
            </motion.button>
          </div>
        </motion.div>

        {/* Featured Vaults */}
        <motion.div
          initial={{ y: 50, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.4, duration: 0.8 }}
          className="mb-16"
        >
          <h2 className="text-3xl font-bold text-center mb-12 bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
            Live Vaults
          </h2>
          
          {loading ? (
            <div className="text-center">
              <div className="animate-spin w-12 h-12 border-4 border-cyan-400 border-t-transparent rounded-full mx-auto"></div>
              <p className="text-gray-400 mt-4">Loading secrets...</p>
            </div>
          ) : error ? (
            <div className="text-center text-red-400">
              <p>Error loading vaults: {error}</p>
            </div>
          ) : vaults && vaults.length > 0 ? (
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
              {vaults.map((vault, index) => (
                <VaultCard 
                  key={vault.id} 
                  vault={vault} 
                  index={index}
                  onClick={() => setSelectedVault(vault)}
                />
              ))}
            </div>
          ) : (
            <div className="text-center text-gray-400">
              <p>No vaults available yet. Be the first to create one!</p>
            </div>
          )}
        </motion.div>

        {/* How It Works */}
        <motion.div
          initial={{ y: 50, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.6, duration: 0.8 }}
          className="text-center"
        >
          <h2 className="text-3xl font-bold mb-12 bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
            How It Works
          </h2>
          
          <div className="grid md:grid-cols-3 gap-8">
            <StepCard 
              icon={<Upload className="w-8 h-8" />}
              number="01"
              title="Upload Secret"
              description="Share your story anonymously. Set a funding goal to unlock the full revelation."
            />
            <StepCard 
              icon={<Users className="w-8 h-8" />}
              number="02" 
              title="Community Funds"
              description="Listeners pledge money based on teasers. The more intriguing, the more funding."
            />
            <StepCard 
              icon={<Zap className="w-8 h-8" />}
              number="03"
              title="Get Paid"
              description="When funding goal is met, secret unlocks and you receive payment instantly."
            />
          </div>
        </motion.div>
      </div>

      {/* Vault Detail Modal */}
      <AnimatePresence>
        {selectedVault && (
          <VaultDetailModal 
            vault={selectedVault} 
            onClose={() => setSelectedVault(null)}
            user={user}
            apiCall={apiCall}
            onLogin={() => setShowLogin(true)}
          />
        )}
      </AnimatePresence>

      {/* Login Modal */}
      <AnimatePresence>
        {showLogin && (
          <LoginModal 
            onClose={() => setShowLogin(false)}
            onSuccess={(userData) => {
              setShowLogin(false);
              onNavigate('landing', userData);
            }}
            onSignupClick={() => {
              setShowLogin(false);
              onNavigate('onboarding');
            }}
            apiCall={apiCall}
          />
        )}
      </AnimatePresence>
    </motion.div>
  );
};

// Vault Card Component
const VaultCard = ({ vault, index, onClick }) => {
  const progressPercentage = vault.progress_percentage || 0;
  
  return (
    <motion.div
      initial={{ y: 50, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ delay: index * 0.1, duration: 0.6 }}
      whileHover={{ 
        scale: 1.02,
        boxShadow: "0 20px 40px rgba(59, 130, 246, 0.2)"
      }}
      onClick={onClick}
      className="group relative bg-gradient-to-br from-slate-800/50 to-blue-900/30 rounded-2xl border border-cyan-500/20 p-6 cursor-pointer backdrop-blur-sm hover:border-cyan-400/40 transition-all duration-300"
    >
      {/* Glowing border effect */}
      <div className="absolute inset-0 bg-gradient-to-r from-cyan-400/20 to-purple-500/20 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300 blur-sm"></div>
      
      <div className="relative z-10">
        {/* Content */}
        <h3 className="text-xl font-bold mb-2 text-white group-hover:text-cyan-300 transition-colors">
          {vault.title}
        </h3>
        <p className="text-gray-400 mb-4 text-sm leading-relaxed">
          {vault.preview}
        </p>

        {/* Category */}
        <div className="mb-4">
          <span className="px-3 py-1 bg-purple-600/80 rounded-full text-sm font-medium">
            {vault.category}
          </span>
        </div>

        {/* Progress */}
        <div className="mb-4">
          <div className="flex justify-between text-sm mb-2">
            <span className="text-gray-300">₹{vault.pledged_amount?.toLocaleString()}</span>
            <span className="text-gray-400">₹{vault.funding_goal?.toLocaleString()}</span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-2">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${progressPercentage}%` }}
              transition={{ delay: index * 0.1 + 0.5, duration: 1, ease: "easeOut" }}
              className="bg-gradient-to-r from-cyan-400 to-purple-500 h-2 rounded-full shadow-lg shadow-cyan-400/30"
            ></motion.div>
          </div>
        </div>

        {/* Stats */}
        <div className="flex justify-between items-center text-sm">
          <div className="flex items-center space-x-4">
            <span className="flex items-center space-x-1 text-gray-400">
              <Users className="w-4 h-4" />
              <span>{vault.backers_count}</span>
            </span>
            <span className="flex items-center space-x-1 text-gray-400">
              <Clock className="w-4 h-4" />
              <span>{vault.time_left}</span>
            </span>
          </div>
          <span className="text-cyan-400 font-medium">
            {progressPercentage.toFixed(0)}% funded
          </span>
        </div>
      </div>
    </motion.div>
  );
};

// Step Card Component
const StepCard = ({ icon, number, title, description }) => {
  return (
    <motion.div
      whileHover={{ y: -10, scale: 1.02 }}
      className="relative bg-gradient-to-br from-slate-800/30 to-blue-900/20 rounded-2xl border border-cyan-500/20 p-8 text-center backdrop-blur-sm hover:border-cyan-400/40 transition-all duration-300"
    >
      <div className="absolute top-4 right-4 text-6xl font-bold text-cyan-400/10">
        {number}
      </div>
      
      <div className="relative z-10">
        <div className="w-16 h-16 bg-gradient-to-r from-cyan-400 to-purple-500 rounded-full flex items-center justify-center mx-auto mb-6 shadow-lg shadow-cyan-400/30">
          {icon}
        </div>
        <h3 className="text-xl font-bold mb-4 text-white">{title}</h3>
        <p className="text-gray-400 leading-relaxed">{description}</p>
      </div>
    </motion.div>
  );
};

// Vault Detail Modal Component
const VaultDetailModal = ({ vault, onClose, user, apiCall, onLogin }) => {
  const [pledgeAmount, setPledgeAmount] = useState(1000);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const progressPercentage = vault.progress_percentage || 0;

  const handlePledge = async () => {
    if (!user) {
      onLogin();
      return;
    }

    try {
      setLoading(true);
      const response = await apiCall('/pledges', {
        method: 'POST',
        body: JSON.stringify({
          vault_id: vault.id,
          amount: pledgeAmount
        })
      });

      if (response.success) {
        setMessage('Pledge successful! 🎉');
        setTimeout(() => {
          onClose();
          window.location.reload(); // Refresh to show updated data
        }, 2000);
      }
    } catch (error) {
      setMessage('Failed to pledge. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.8, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.8, opacity: 0 }}
        onClick={(e) => e.stopPropagation()}
        className="bg-gradient-to-br from-slate-900 to-blue-950 rounded-3xl border border-cyan-500/30 p-8 max-w-2xl w-full max-h-[90vh] overflow-y-auto"
      >
        {/* Header */}
        <div className="relative mb-6">
          <h2 className="text-3xl font-bold text-white mb-2">{vault.title}</h2>
          <span className="px-3 py-1 bg-purple-600 rounded-full text-sm font-medium">
            {vault.category}
          </span>
          <button
            onClick={onClose}
            className="absolute top-0 right-0 w-10 h-10 bg-black/50 rounded-full flex items-center justify-center text-white hover:bg-black/70 transition-colors"
          >
            ×
          </button>
        </div>

        {/* Description */}
        <p className="text-gray-300 mb-6">{vault.description}</p>

        {/* Progress Section */}
        <div className="mb-8 text-center">
          <div className="relative w-48 h-48 mx-auto mb-6">
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
              <circle
                cx="50"
                cy="50"
                r="45"
                stroke="rgba(59, 130, 246, 0.1)"
                strokeWidth="8"
                fill="none"
              />
              <motion.circle
                cx="50"
                cy="50"
                r="45"
                stroke="url(#gradient)"
                strokeWidth="8"
                fill="none"
                strokeLinecap="round"
                initial={{ strokeDasharray: "0 283" }}
                animate={{ strokeDasharray: `${(progressPercentage * 283) / 100} 283` }}
                transition={{ duration: 1.5, ease: "easeOut" }}
              />
              <defs>
                <linearGradient id="gradient" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#06b6d4" />
                  <stop offset="100%" stopColor="#8b5cf6" />
                </linearGradient>
              </defs>
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-3xl font-bold text-white">{progressPercentage.toFixed(0)}%</span>
              <span className="text-gray-400">Funded</span>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-8">
            <div>
              <div className="text-2xl font-bold text-cyan-400">₹{vault.pledged_amount?.toLocaleString()}</div>
              <div className="text-gray-400">Raised</div>
            </div>
            <div>
              <div className="text-2xl font-bold text-purple-400">₹{vault.funding_goal?.toLocaleString()}</div>
              <div className="text-gray-400">Goal</div>
            </div>
          </div>
        </div>

        {message && (
          <div className="mb-6 p-4 bg-green-500/20 border border-green-500/40 rounded-xl text-green-300 text-center">
            {message}
          </div>
        )}

        {/* Pledge Section */}
        <div className="space-y-6">
          <div>
            <label className="block text-white font-medium mb-3">Pledge Amount</label>
            <div className="relative">
              <input
                type="range"
                min="100"
                max="10000"
                step="100"
                value={pledgeAmount}
                onChange={(e) => setPledgeAmount(Number(e.target.value))}
                className="w-full h-2 bg-slate-700 rounded-lg appearance-none cursor-pointer slider"
              />
              <div className="flex justify-between text-sm text-gray-400 mt-2">
                <span>₹100</span>
                <span className="text-cyan-400 font-bold text-lg">₹{pledgeAmount.toLocaleString()}</span>
                <span>₹10,000</span>
              </div>
            </div>
          </div>

          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            onClick={handlePledge}
            disabled={loading}
            className="w-full py-4 bg-gradient-to-r from-cyan-600 to-purple-600 rounded-xl text-white font-semibold text-lg shadow-lg shadow-purple-500/25 flex items-center justify-center space-x-2 disabled:opacity-50"
          >
            {loading ? (
              <div className="animate-spin w-5 h-5 border-2 border-white border-t-transparent rounded-full"></div>
            ) : (
              <>
                <DollarSign className="w-5 h-5" />
                <span>{user ? `Pledge ₹${pledgeAmount.toLocaleString()}` : 'Login to Pledge'}</span>
              </>
            )}
          </motion.button>

          <p className="text-center text-sm text-gray-400">
            If the goal isn't reached, you'll get a full refund
          </p>
        </div>
      </motion.div>
    </motion.div>
  );
};

// Login Modal Component
const LoginModal = ({ onClose, onSuccess, onSignupClick, apiCall }) => {
  const [isLogin, setIsLogin] = useState(true);
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    username: '',
    user_type: 'listener'
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const endpoint = isLogin ? '/auth/login' : '/auth/register';
      const payload = isLogin 
        ? { email: formData.email, password: formData.password }
        : formData;

      console.log('Submitting to:', endpoint, 'with data:', payload);

      const response = await apiCall(endpoint, {
        method: 'POST',
        body: JSON.stringify(payload)
      });

      console.log('Response:', response);

      if (response.success) {
        onSuccess({
          user: response.data.user,
          token: response.data.access_token
        });
      } else {
        setError(response.message || (isLogin ? 'Invalid credentials' : 'Registration failed'));
      }
    } catch (error) {
      console.error('Auth error:', error);
      setError(isLogin ? 'Invalid credentials' : 'Registration failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.8, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.8, opacity: 0 }}
        onClick={(e) => e.stopPropagation()}
        className="bg-gradient-to-br from-slate-900 to-blue-950 rounded-3xl border border-cyan-500/30 p-8 max-w-md w-full"
      >
        <div className="text-center mb-6">
          <h2 className="text-3xl font-bold text-white mb-2">
            {isLogin ? 'Welcome Back' : 'Join HushHush'}
          </h2>
          <p className="text-gray-400">
            {isLogin ? 'Sign in to your account' : 'Create your account'}
          </p>
        </div>

        {error && (
          <div className="mb-4 p-3 bg-red-500/20 border border-red-500/40 rounded-xl text-red-300 text-center">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          {!isLogin && (
            <input
              type="text"
              placeholder="Username"
              value={formData.username}
              onChange={(e) => setFormData({...formData, username: e.target.value})}
              className="w-full p-4 bg-slate-800/50 border border-cyan-500/20 rounded-xl text-white placeholder-gray-400 focus:border-cyan-400/50 focus:outline-none transition-colors"
              required
            />
          )}
          
          <input
            type="email"
            placeholder="Email"
            value={formData.email}
            onChange={(e) => setFormData({...formData, email: e.target.value})}
            className="w-full p-4 bg-slate-800/50 border border-cyan-500/20 rounded-xl text-white placeholder-gray-400 focus:border-cyan-400/50 focus:outline-none transition-colors"
            required
          />
          
          <input
            type="password"
            placeholder="Password"
            value={formData.password}
            onChange={(e) => setFormData({...formData, password: e.target.value})}
            className="w-full p-4 bg-slate-800/50 border border-cyan-500/20 rounded-xl text-white placeholder-gray-400 focus:border-cyan-400/50 focus:outline-none transition-colors"
            required
          />

          {!isLogin && (
            <select
              value={formData.user_type}
              onChange={(e) => setFormData({...formData, user_type: e.target.value})}
              className="w-full p-4 bg-slate-800/50 border border-cyan-500/20 rounded-xl text-white focus:border-cyan-400/50 focus:outline-none transition-colors"
            >
              <option value="listener">Listener (Fund Secrets)</option>
              <option value="whisperer">Whisperer (Share Secrets)</option>
              <option value="both">Both</option>
            </select>
          )}

          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            type="submit"
            disabled={loading}
            className="w-full py-4 bg-gradient-to-r from-cyan-600 to-purple-600 rounded-xl text-white font-semibold text-lg shadow-lg shadow-purple-500/25 flex items-center justify-center disabled:opacity-50"
          >
            {loading ? (
              <div className="animate-spin w-5 h-5 border-2 border-white border-t-transparent rounded-full"></div>
            ) : (
              isLogin ? 'Sign In' : 'Create Account'
            )}
          </motion.button>
        </form>

        <div className="text-center mt-6">
          <p className="text-gray-400">
            {isLogin ? "Don't have an account?" : "Already have an account?"}
            <button
              onClick={() => {
                setIsLogin(!isLogin);
                setError('');
              }}
              className="ml-2 text-cyan-400 hover:text-cyan-300 transition-colors"
            >
              {isLogin ? 'Sign up' : 'Sign in'}
            </button>
          </p>
        </div>
      </motion.div>
    </motion.div>
  );
};

// Whisperer Onboarding Component (Updated)
const WhispererOnboarding = ({ onNavigate, onComplete, apiCall }) => {
  const [currentStep, setCurrentStep] = useState(0);
  const [formData, setFormData] = useState({
    email: '',
    username: '',
    password: '',
    bio: '',
    user_type: 'whisperer'
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const steps = [
    {
      title: "Welcome, Future Whisperer",
      subtitle: "Let's get you set up to share your secrets",
      icon: <Shield className="w-12 h-12" />,
      status: "ready"
    },
    {
      title: "Verify Your Identity", 
      subtitle: "We keep you anonymous but need to verify you're real",
      icon: <CheckCircle className="w-12 h-12" />,
      status: "verifying"
    },
    {
      title: "Create Your Profile",
      subtitle: "Set up your anonymous whisperer persona", 
      icon: <Eye className="w-12 h-12" />,
      status: "setup"
    }
  ];

  const handleNext = async () => {
    if (currentStep < steps.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
      // Register the user
      try {
        setLoading(true);
        setError('');

        console.log('Registering user with data:', formData);

        const response = await apiCall('/auth/register', {
          method: 'POST',
          body: JSON.stringify(formData)
        });

        console.log('Registration response:', response);

        if (response.success) {
          onComplete({
            user: response.data.user,
            token: response.data.access_token
          });
        } else {
          setError(response.message || 'Registration failed. Please try again.');
        }
      } catch (error) {
        console.error('Registration error:', error);
        setError('Registration failed. Please check your internet connection and try again.');
      } finally {
        setLoading(false);
      }
    }
  };

  const getStepColor = (step) => {
    if (step.status === "ready") return "from-emerald-500 to-teal-500";
    if (step.status === "verifying") return "from-amber-500 to-orange-500";
    if (step.status === "setup") return "from-purple-500 to-pink-500";
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="min-h-screen flex items-center justify-center p-6 relative overflow-hidden"
    >
      {/* Background */}
      <div className="absolute inset-0 bg-gradient-to-br from-slate-950 via-blue-950 to-purple-950"></div>
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_70%_80%,rgba(168,85,247,0.15),transparent)] blur-xl"></div>

      <div className="relative z-10 w-full max-w-2xl">
        {/* Header */}
        <div className="text-center mb-12">
          <button
            onClick={() => onNavigate('landing')}
            className="inline-flex items-center space-x-2 text-gray-400 hover:text-white transition-colors mb-8"
          >
            <ArrowRight className="w-4 h-4 rotate-180" />
            <span>Back to HushHush</span>
          </button>
          
          <div className="flex items-center justify-center space-x-2 mb-6">
            <div className="w-8 h-8 bg-gradient-to-r from-cyan-400 to-purple-500 rounded-full flex items-center justify-center">
              <Lock className="w-4 h-4 text-white" />
            </div>
            <span className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
              HushHush
            </span>
          </div>
          
          <div className="flex justify-center space-x-4 mb-8">
            {steps.map((step, index) => (
              <div
                key={index}
                className={`w-3 h-3 rounded-full transition-all duration-300 ${
                  index <= currentStep ? 'bg-cyan-400' : 'bg-gray-600'
                }`}
              />
            ))}
          </div>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-500/20 border border-red-500/40 rounded-xl text-red-300 text-center">
            {error}
          </div>
        )}

        {/* Step Content */}
        <AnimatePresence mode="wait">
          <motion.div
            key={currentStep}
            initial={{ x: 50, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: -50, opacity: 0 }}
            transition={{ duration: 0.3 }}
            className="text-center"
          >
            <div className={`w-32 h-32 bg-gradient-to-r ${getStepColor(steps[currentStep])} rounded-full flex items-center justify-center mx-auto mb-8 shadow-lg`}>
              {steps[currentStep].icon}
            </div>

            <h1 className="text-4xl font-bold text-white mb-4">
              {steps[currentStep].title}
            </h1>
            <p className="text-xl text-gray-300 mb-12">
              {steps[currentStep].subtitle}
            </p>

            {/* Step-specific content */}
            {currentStep === 0 && (
              <div className="space-y-6">
                <p className="text-gray-400 leading-relaxed max-w-lg mx-auto">
                  Join thousands of whisperers who are monetizing their secrets. 
                  Your identity stays hidden, but your stories get the audience they deserve.
                </p>
              </div>
            )}

            {currentStep === 1 && (
              <div className="space-y-6">
                <div className="bg-gradient-to-br from-slate-800/50 to-blue-900/30 rounded-2xl border border-cyan-500/20 p-8 backdrop-blur-sm">
                  <AlertCircle className="w-12 h-12 text-amber-400 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-white mb-3">Identity Verification</h3>
                  <p className="text-gray-400 mb-6">
                    We use bank-grade security to verify your identity while keeping you completely anonymous to other users.
                  </p>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-lg">
                      <span className="text-emerald-400">Document Verification</span>
                      <CheckCircle className="w-5 h-5 text-emerald-400" />
                    </div>
                    <div className="flex items-center justify-between p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-lg">
                      <span className="text-emerald-400">Face Match</span>
                      <CheckCircle className="w-5 h-5 text-emerald-400" />
                    </div>
                  </div>
                </div>
              </div>
            )}

            {currentStep === 2 && (
              <div className="space-y-6">
                <div className="space-y-4">
                  <input
                    type="email"
                    placeholder="Your email"
                    value={formData.email}
                    onChange={(e) => setFormData({...formData, email: e.target.value})}
                    className="w-full p-4 bg-slate-800/50 border border-cyan-500/20 rounded-xl text-white placeholder-gray-400 focus:border-cyan-400/50 focus:outline-none transition-colors"
                  />
                  <input
                    type="text"
                    placeholder="Your anonymous username"
                    value={formData.username}
                    onChange={(e) => setFormData({...formData, username: e.target.value})}
                    className="w-full p-4 bg-slate-800/50 border border-cyan-500/20 rounded-xl text-white placeholder-gray-400 focus:border-cyan-400/50 focus:outline-none transition-colors"
                  />
                  <input
                    type="password"
                    placeholder="Create a password"
                    value={formData.password}
                    onChange={(e) => setFormData({...formData, password: e.target.value})}
                    className="w-full p-4 bg-slate-800/50 border border-cyan-500/20 rounded-xl text-white placeholder-gray-400 focus:border-cyan-400/50 focus:outline-none transition-colors"
                  />
                  <textarea
                    placeholder="Tell listeners what kind of secrets you share..."
                    value={formData.bio}
                    onChange={(e) => setFormData({...formData, bio: e.target.value})}
                    rows={4}
                    className="w-full p-4 bg-slate-800/50 border border-cyan-500/20 rounded-xl text-white placeholder-gray-400 focus:border-cyan-400/50 focus:outline-none transition-colors resize-none"
                  />
                </div>
              </div>
            )}

            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={handleNext}
              disabled={loading}
              className={`px-12 py-4 bg-gradient-to-r ${getStepColor(steps[currentStep])} rounded-full text-white font-semibold text-lg shadow-lg flex items-center space-x-2 mx-auto disabled:opacity-50`}
            >
              {loading ? (
                <div className="animate-spin w-5 h-5 border-2 border-white border-t-transparent rounded-full"></div>
              ) : (
                <>
                  <span>{currentStep === steps.length - 1 ? "Complete Setup" : "Continue"}</span>
                  <ArrowRight className="w-5 h-5" />
                </>
              )}
            </motion.button>
          </motion.div>
        </AnimatePresence>
      </div>
    </motion.div>
  );
};

// Vault Creation Component (Updated)
const VaultCreation = ({ onNavigate, user, onVaultCreated, apiCall }) => {
  const [currentStep, setCurrentStep] = useState(0);
  const [vaultData, setVaultData] = useState({
    title: '',
    description: '',
    category: 'Unhinged',
    secret_type: 'text',
    content: '',
    preview: '',
    funding_goal: 25000,
    duration_days: 14,
    content_warnings: [],
    tags: []
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const steps = [
    { title: "Upload Secret", icon: <Upload className="w-8 h-8" /> },
    { title: "Add Details", icon: <Target className="w-8 h-8" /> },
    { title: "Set Goal", icon: <DollarSign className="w-8 h-8" /> },
    { title: "Preview", icon: <Eye className="w-8 h-8" /> }
  ];

  const handleNext = async () => {
    if (currentStep < steps.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
      // Create vault
      try {
        setLoading(true);
        const response = await apiCall('/vaults', {
          method: 'POST',
          body: JSON.stringify(vaultData)
        });

        if (response.success) {
          onVaultCreated(response.data);
        }
      } catch (error) {
        setError('Failed to create vault. Please try again.');
      } finally {
        setLoading(false);
      }
    }
  };

  const handleBack = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    } else {
      onNavigate('landing');
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="min-h-screen p-6 relative overflow-hidden"
    >
      {/* Background */}
      <div className="absolute inset-0 bg-gradient-to-br from-slate-950 via-blue-950 to-purple-950"></div>
      
      <div className="relative z-10 max-w-4xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-12">
          <button
            onClick={handleBack}
            className="flex items-center space-x-2 text-gray-400 hover:text-white transition-colors"
          >
            <ArrowRight className="w-4 h-4 rotate-180" />
            <span>Back</span>
          </button>
          
          <div className="flex items-center space-x-2">
            <div className="w-8 h-8 bg-gradient-to-r from-cyan-400 to-purple-500 rounded-full flex items-center justify-center">
              <Lock className="w-4 h-4 text-white" />
            </div>
            <span className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
              Create Vault
            </span>
          </div>
          
          <div className="text-gray-400">
            Step {currentStep + 1} of {steps.length}
          </div>
        </div>

        {/* Progress */}
        <div className="flex justify-between mb-12">
          {steps.map((step, index) => (
            <div key={index} className="flex flex-col items-center">
              <div className={`w-12 h-12 rounded-full flex items-center justify-center mb-2 transition-all duration-300 ${
                index <= currentStep 
                  ? 'bg-gradient-to-r from-cyan-400 to-purple-500 text-white' 
                  : 'bg-slate-700 text-gray-400'
              }`}>
                {step.icon}
              </div>
              <span className={`text-sm font-medium ${
                index <= currentStep ? 'text-white' : 'text-gray-500'
              }`}>
                {step.title}
              </span>
            </div>
          ))}
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-500/20 border border-red-500/40 rounded-xl text-red-300 text-center">
            {error}
          </div>
        )}

        {/* Step Content */}
        <AnimatePresence mode="wait">
          <motion.div
            key={currentStep}
            initial={{ x: 50, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: -50, opacity: 0 }}
            transition={{ duration: 0.3 }}
            className="bg-gradient-to-br from-slate-800/50 to-blue-900/30 rounded-3xl border border-cyan-500/20 p-8 backdrop-blur-sm"
          >
            {/* Step 0: Upload Secret */}
            {currentStep === 0 && (
              <div className="space-y-6">
                <h2 className="text-3xl font-bold text-white mb-6">Upload Your Secret</h2>
                
                <div className="space-y-4">
                  <div className="flex space-x-4">
                    <button
                      onClick={() => setVaultData({...vaultData, secret_type: 'text'})}
                      className={`flex-1 p-4 rounded-xl border-2 transition-all ${
                        vaultData.secret_type === 'text'
                          ? 'border-cyan-400 bg-cyan-400/10'
                          : 'border-gray-600 bg-slate-700/50'
                      }`}
                    >
                      <div className="text-center">
                        <div className="text-2xl mb-2">📝</div>
                        <div className="text-white font-medium">Text Secret</div>
                      </div>
                    </button>
                    <button
                      onClick={() => setVaultData({...vaultData, secret_type: 'audio'})}
                      className={`flex-1 p-4 rounded-xl border-2 transition-all ${
                        vaultData.secret_type === 'audio'
                          ? 'border-cyan-400 bg-cyan-400/10'
                          : 'border-gray-600 bg-slate-700/50'
                      }`}
                    >
                      <div className="text-center">
                        <div className="text-2xl mb-2">🎙️</div>
                        <div className="text-white font-medium">Audio Secret</div>
                      </div>
                    </button>
                  </div>

                  {vaultData.secret_type === 'text' ? (
                    <textarea
                      placeholder="Share your secret here... The more intriguing, the more funding you'll get."
                      value={vaultData.content}
                      onChange={(e) => setVaultData({...vaultData, content: e.target.value})}
                      rows={8}
                      className="w-full p-4 bg-slate-800/50 border border-cyan-500/20 rounded-xl text-white placeholder-gray-400 focus:border-cyan-400/50 focus:outline-none transition-colors resize-none"
                    />
                  ) : (
                    <div className="border-2 border-dashed border-cyan-500/30 rounded-xl p-12 text-center hover:border-cyan-400/50 transition-colors">
                      <Mic className="w-16 h-16 text-cyan-400 mx-auto mb-4" />
                      <h3 className="text-xl font-semibold text-white mb-2">Drop your audio file here</h3>
                      <p className="text-gray-400">Supports MP3, WAV, M4A up to 50MB</p>
                      <button className="mt-4 px-6 py-2 bg-gradient-to-r from-cyan-600 to-purple-600 rounded-lg text-white font-medium">
                        Choose File
                      </button>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Step 1: Add Details */}
            {currentStep === 1 && (
              <div className="space-y-6">
                <h2 className="text-3xl font-bold text-white mb-6">Add Details</h2>
                
                <div className="space-y-4">
                  <div>
                    <label className="block text-white font-medium mb-2">Vault Title</label>
                    <input
                      type="text"
                      placeholder="Give your secret a compelling title..."
                      value={vaultData.title}
                      onChange={(e) => setVaultData({...vaultData, title: e.target.value})}
                      className="w-full p-4 bg-slate-800/50 border border-cyan-500/20 rounded-xl text-white placeholder-gray-400 focus:border-cyan-400/50 focus:outline-none transition-colors"
                    />
                  </div>

                  <div>
                    <label className="block text-white font-medium mb-2">Description</label>
                    <textarea
                      placeholder="Describe what makes this secret worth funding..."
                      value={vaultData.description}
                      onChange={(e) => setVaultData({...vaultData, description: e.target.value})}
                      rows={4}
                      className="w-full p-4 bg-slate-800/50 border border-cyan-500/20 rounded-xl text-white placeholder-gray-400 focus:border-cyan-400/50 focus:outline-none transition-colors resize-none"
                    />
                  </div>

                  <div>
                    <label className="block text-white font-medium mb-2">Category</label>
                    <select
                      value={vaultData.category}
                      onChange={(e) => setVaultData({...vaultData, category: e.target.value})}
                      className="w-full p-4 bg-slate-800/50 border border-cyan-500/20 rounded-xl text-white focus:border-cyan-400/50 focus:outline-none transition-colors"
                    >
                      <option value="Unhinged">Unhinged</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-white font-medium mb-2">Teaser Preview</label>
                    <textarea
                      placeholder="Give a brief, tantalizing preview without revealing the full secret..."
                      value={vaultData.preview}
                      onChange={(e) => setVaultData({...vaultData, preview: e.target.value})}
                      rows={3}
                      className="w-full p-4 bg-slate-800/50 border border-cyan-500/20 rounded-xl text-white placeholder-gray-400 focus:border-cyan-400/50 focus:outline-none transition-colors resize-none"
                    />
                  </div>
                </div>
              </div>
            )}

            {/* Step 2: Set Goal */}
            {currentStep === 2 && (
              <div className="space-y-6">
                <h2 className="text-3xl font-bold text-white mb-6">Set Funding Goal</h2>
                
                <div className="space-y-6">
                  <div>
                    <label className="block text-white font-medium mb-3">
                      Funding Goal: ₹{vaultData.funding_goal.toLocaleString()}
                    </label>
                    <input
                      type="range"
                      min="5000"
                      max="100000"
                      step="5000"
                      value={vaultData.funding_goal}
                      onChange={(e) => setVaultData({...vaultData, funding_goal: Number(e.target.value)})}
                      className="w-full h-3 bg-slate-700 rounded-lg appearance-none cursor-pointer slider"
                    />
                    <div className="flex justify-between text-sm text-gray-400 mt-2">
                      <span>₹5,000</span>
                      <span>₹1,00,000</span>
                    </div>
                  </div>

                  <div>
                    <label className="block text-white font-medium mb-3">
                      Duration: {vaultData.duration_days} days
                    </label>
                    <input
                      type="range"
                      min="3"
                      max="30"
                      step="1"
                      value={vaultData.duration_days}
                      onChange={(e) => setVaultData({...vaultData, duration_days: Number(e.target.value)})}
                      className="w-full h-3 bg-slate-700 rounded-lg appearance-none cursor-pointer slider"
                    />
                    <div className="flex justify-between text-sm text-gray-400 mt-2">
                      <span>3 days</span>
                      <span>30 days</span>
                    </div>
                  </div>

                  <div className="bg-slate-800/50 border border-cyan-500/20 rounded-xl p-6">
                    <h3 className="text-lg font-semibold text-white mb-4">Breakdown</h3>
                    <div className="space-y-2 text-gray-300">
                      <div className="flex justify-between">
                        <span>Funding Goal</span>
                        <span>₹{vaultData.funding_goal.toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Platform Fee (5%)</span>
                        <span>-₹{(vaultData.funding_goal * 0.05).toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Credibility Bond (5%)</span>
                        <span>-₹{(vaultData.funding_goal * 0.05).toLocaleString()}</span>
                      </div>
                      <hr className="border-gray-600" />
                      <div className="flex justify-between text-cyan-400 font-semibold">
                        <span>You'll Receive</span>
                        <span>₹{(vaultData.funding_goal * 0.9).toLocaleString()}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Step 3: Preview */}
            {currentStep === 3 && (
              <div className="space-y-6">
                <h2 className="text-3xl font-bold text-white mb-6">Preview Your Vault</h2>
                
                <div className="bg-gradient-to-br from-slate-700/50 to-blue-800/30 rounded-2xl border border-cyan-500/20 p-6">
                  <div className="flex items-start space-x-4 mb-4">
                    <div className="w-16 h-16 bg-gradient-to-r from-cyan-400 to-purple-500 rounded-full flex items-center justify-center">
                      <Lock className="w-8 h-8 text-white" />
                    </div>
                    <div className="flex-1">
                      <h3 className="text-xl font-bold text-white mb-2">{vaultData.title}</h3>
                      <span className="px-3 py-1 bg-purple-600 rounded-full text-sm font-medium">
                        {vaultData.category}
                      </span>
                    </div>
                  </div>

                  <p className="text-gray-300 mb-6 leading-relaxed">{vaultData.preview}</p>

                  <div className="grid grid-cols-3 gap-4 mb-6">
                    <div className="text-center">
                      <div className="text-2xl font-bold text-cyan-400">₹{vaultData.funding_goal.toLocaleString()}</div>
                      <div className="text-gray-400 text-sm">Goal</div>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-purple-400">{vaultData.duration_days}</div>
                      <div className="text-gray-400 text-sm">Days</div>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-green-400">0</div>
                      <div className="text-gray-400 text-sm">Backers</div>
                    </div>
                  </div>

                  <div className="w-full bg-slate-700 rounded-full h-3 mb-4">
                    <div className="w-0 bg-gradient-to-r from-cyan-400 to-purple-500 h-3 rounded-full"></div>
                  </div>

                  <div className="flex justify-between text-sm text-gray-400">
                    <span>₹0 raised</span>
                    <span>0% funded</span>
                  </div>
                </div>

                <div className="bg-amber-500/10 border border-amber-500/20 rounded-xl p-4">
                  <div className="flex items-center space-x-2 text-amber-400">
                    <AlertCircle className="w-5 h-5" />
                    <span className="font-medium">Ready to Launch</span>
                  </div>
                  <p className="text-amber-200 text-sm mt-2">
                    Your vault will be live immediately. Make sure all details are correct before proceeding.
                  </p>
                </div>
              </div>
            )}

            {/* Navigation */}
            <div className="flex justify-between mt-8">
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={handleBack}
                className="px-6 py-3 border border-gray-600 rounded-xl text-gray-300 hover:border-gray-500 hover:text-white transition-colors"
              >
                {currentStep === 0 ? 'Cancel' : 'Back'}
              </motion.button>
              
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={handleNext}
                disabled={loading}
                className="px-8 py-3 bg-gradient-to-r from-cyan-600 to-purple-600 rounded-xl text-white font-semibold shadow-lg shadow-purple-500/25 disabled:opacity-50 flex items-center space-x-2"
              >
                {loading ? (
                  <div className="animate-spin w-5 h-5 border-2 border-white border-t-transparent rounded-full"></div>
                ) : (
                  <span>{currentStep === steps.length - 1 ? 'Launch Vault' : 'Continue'}</span>
                )}
              </motion.button>
            </div>
          </motion.div>
        </AnimatePresence>
      </div>

      <style jsx>{`
        .slider::-webkit-slider-thumb {
          appearance: none;
          height: 20px;
          width: 20px;
          border-radius: 50%;
          background: linear-gradient(45deg, #06b6d4, #8b5cf6);
          cursor: pointer;
          box-shadow: 0 0 10px rgba(59, 130, 246, 0.5);
        }
        
        .slider::-moz-range-thumb {
          height: 20px;
          width: 20px;
          border-radius: 50%;
          background: linear-gradient(45deg, #06b6d4, #8b5cf6);
          cursor: pointer;
          border: none;
          box-shadow: 0 0 10px rgba(59, 130, 246, 0.5);
        }
      `}</style>
    </motion.div>
  );
};

// Export components
export default LandingPage;
export { WhispererOnboarding, VaultCreation };