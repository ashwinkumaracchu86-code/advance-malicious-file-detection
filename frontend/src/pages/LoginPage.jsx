import { useState, useRef, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { FiLock, FiUser, FiAlertTriangle, FiMail, FiEye, FiEyeOff, FiCheck, FiX } from 'react-icons/fi';
import toast from 'react-hot-toast';
import { useAuth } from '../context/AuthContext';
import { authAPI } from '../services/api';

function AnimatedBackground() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let animId;
    let particles = [];
    let connections = [];
    let mouse = { x: -1000, y: -1000 };

    const resize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resize();
    window.addEventListener('resize', resize);

    const PARTICLE_COUNT = Math.min(80, Math.floor(window.innerWidth / 15));
    for (let i = 0; i < PARTICLE_COUNT; i++) {
      particles.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        size: Math.random() * 1.5 + 0.5,
        opacity: Math.random() * 0.5 + 0.2,
      });
    }

    const handleMouseMove = (e) => { mouse.x = e.clientX; mouse.y = e.clientY; };
    window.addEventListener('mousemove', handleMouseMove);

    const animate = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      const grad = ctx.createRadialGradient(
        canvas.width * 0.3, canvas.height * 0.3, 0,
        canvas.width * 0.3, canvas.height * 0.3, canvas.width * 0.7
      );
      grad.addColorStop(0, 'rgba(6, 182, 212, 0.03)');
      grad.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      particles.forEach((p) => {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0) p.x = canvas.width;
        if (p.x > canvas.width) p.x = 0;
        if (p.y < 0) p.y = canvas.height;
        if (p.y > canvas.height) p.y = 0;

        const dx = mouse.x - p.x;
        const dy = mouse.y - p.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 150) {
          const force = (150 - dist) / 150;
          p.vx -= (dx / dist) * force * 0.02;
          p.vy -= (dy / dist) * force * 0.02;
        }

        p.vx *= 0.99;
        p.vy *= 0.99;

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(100, 200, 255, ${p.opacity})`;
        ctx.fill();
      });

      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 120) {
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.strokeStyle = `rgba(6, 182, 212, ${0.08 * (1 - dist / 120)})`;
            ctx.lineWidth = 0.5;
            ctx.stroke();
          }
        }
      }

      animId = requestAnimationFrame(animate);
    };
    animate();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', resize);
      window.removeEventListener('mousemove', handleMouseMove);
    };
  }, []);

  return <canvas ref={canvasRef} className="fixed inset-0 w-full h-full pointer-events-none" aria-hidden="true" />;
}

export default function LoginPage() {
  const [loginType, setLoginType] = useState(null);
  const [isRegister, setIsRegister] = useState(false);
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const { login } = useAuth();

  const passwordChecks = useMemo(() => ({
    length: password.length >= 8,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    digit: /\d/.test(password),
    special: /[!@#$%^&*(),.?":{}|<>]/.test(password),
  }), [password]);

  const passwordStrength = useMemo(() => {
    const passed = Object.values(passwordChecks).filter(Boolean).length;
    if (passed <= 2) return { label: 'Weak', color: 'text-red-400', bg: 'bg-red-500' };
    if (passed <= 3) return { label: 'Fair', color: 'text-yellow-400', bg: 'bg-yellow-500' };
    if (passed <= 4) return { label: 'Good', color: 'text-blue-400', bg: 'bg-blue-500' };
    return { label: 'Strong', color: 'text-green-400', bg: 'bg-green-500' };
  }, [passwordChecks]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (isRegister) {
      if (!username.trim() || !email.trim() || !password.trim()) {
        setError('Please fill in all fields');
        toast.error('Please fill in all fields');
        return;
      }
      setLoading(true);
      try {
        await authAPI.register({ username, email, password });
        toast.success('Registration successful! Please sign in.');
        setIsRegister(false);
        setEmail('');
        setPassword('');
      } catch (err) {
        const detail = err.response?.data?.detail;
        let msg;
        if (detail && typeof detail === 'object' && detail.errors) {
          msg = detail.errors.join('. ');
        } else {
          msg = detail || err.message || 'Registration failed';
        }
        setError(msg);
        toast.error(msg);
      } finally {
        setLoading(false);
      }
    } else {
      if (!username.trim() || !password.trim()) {
        setError('Please enter both username and password');
        toast.error('Please enter both username and password');
        return;
      }
      setLoading(true);
      try {
        const userData = await login(username, password);
        toast.success('Login successful');
        navigate('/dashboard');
      } catch (err) {
        const msg = err.response?.data?.detail || err.message || 'Login failed';
        setError(msg);
        toast.error(msg);
      } finally {
        setLoading(false);
      }
    }
  };

  const toggleMode = () => {
    setIsRegister(!isRegister);
    setError('');
    setUsername('');
    setEmail('');
    setPassword('');
  };

  if (!loginType && !isRegister) {
    return (
      <div className="min-h-screen bg-[#050a18] flex items-center justify-center px-4 relative overflow-hidden">
        <AnimatedBackground />
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="absolute -top-40 -right-40 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl" />
          <div className="absolute -bottom-40 -left-40 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl" />
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-cyan-500/3 rounded-full blur-3xl" />
        </div>
        <div className="w-full max-w-md relative z-10">
          <div className="text-center mb-8">
            <img src="/logo.svg" alt="MFDS Logo" className="w-16 h-16 mx-auto mb-4" />
            <h1 className="text-3xl font-bold text-white tracking-tight">MFDS</h1>
            <p className="text-slate-400 text-sm mt-1">Advanced Malicious File Detection System</p>
          </div>
          <div className="bg-slate-900/60 backdrop-blur-xl border border-slate-700/50 rounded-2xl shadow-2xl shadow-black/40 p-8">
            <div className="mb-6 text-center">
              <h2 className="text-xl font-semibold text-white">Sign In</h2>
              <p className="text-slate-400 text-sm mt-1">Sign in to your account to continue</p>
            </div>
            <button
              onClick={() => { setLoginType('user'); setIsRegister(false); }}
              className="w-full py-3.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold rounded-xl transition-all duration-200 flex items-center justify-center gap-3 shadow-lg shadow-cyan-500/20"
            >
              <FiUser className="w-5 h-5" />
              Sign In
            </button>
            <div className="mt-6 pt-5 border-t border-slate-700/50 text-center">
              <button
                onClick={() => { setIsRegister(true); setLoginType('user'); }}
                className="text-cyan-400 hover:text-cyan-300 text-sm transition-colors font-medium"
              >
                {"Don't have an account? Register"}
              </button>
            </div>
          </div>
          <p className="text-center text-slate-600 text-xs mt-6">
            Protected by Advanced Threat Detection Engine
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#050a18] flex items-center justify-center px-4 relative overflow-hidden">
      <AnimatedBackground />

      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -right-40 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl" />
        <div className="absolute -bottom-40 -left-40 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-cyan-500/3 rounded-full blur-3xl" />
      </div>

      <div className="w-full max-w-md relative z-10">
        <div className="text-center mb-8">
          <img src="/logo.svg" alt="MFDS Logo" className="w-16 h-16 mx-auto mb-4" />
          <h1 className="text-3xl font-bold text-white tracking-tight">MFDS</h1>
          <p className="text-slate-400 text-sm mt-1">Advanced Malicious File Detection System</p>
        </div>

        <div className="bg-slate-900/60 backdrop-blur-xl border border-slate-700/50 rounded-2xl shadow-2xl shadow-black/40 p-8">
            <div className="mb-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-semibold text-white">
                  {isRegister ? 'Create Account' : 'Sign In'}
                </h2>
                <p className="text-slate-400 text-sm mt-1">
                  {isRegister
                    ? 'Register to access the security dashboard'
                    : 'Sign in with your credentials'}
                </p>
              </div>
              <button
                onClick={() => { setLoginType(null); setIsRegister(false); setError(''); setUsername(''); setEmail(''); setPassword(''); }}
                className="text-slate-400 hover:text-white text-xs underline transition-colors"
              >
                Change
              </button>
            </div>
          </div>

          {error && (
            <div className="mb-5 p-3.5 bg-red-500/10 border border-red-500/20 rounded-xl flex items-center gap-2.5 text-red-400 text-sm">
              <FiAlertTriangle className="flex-shrink-0 w-4 h-4" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">Username</label>
              <div className="relative">
                <FiUser className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Enter your username"
                  autoComplete="username"
                  className="w-full pl-11 pr-4 py-3 bg-slate-800/50 border border-slate-600/50 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/30 transition-all text-sm"
                />
              </div>
            </div>

            {isRegister && (
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1.5">Email</label>
                <div className="relative">
                  <FiMail className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="Enter your email"
                    autoComplete="email"
                    className="w-full pl-11 pr-4 py-3 bg-slate-800/50 border border-slate-600/50 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/30 transition-all text-sm"
                  />
                </div>
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">Password</label>
              <div className="relative">
                <FiLock className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={isRegister ? 'Min 8 chars, upper, lower, digit, special' : 'Enter your password'}
                  autoComplete={isRegister ? 'new-password' : 'current-password'}
                  className="w-full pl-11 pr-11 py-3 bg-slate-800/50 border border-slate-600/50 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/30 transition-all text-sm"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                >
                  {showPassword ? <FiEyeOff className="w-4 h-4" /> : <FiEye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {isRegister && password.length > 0 && (
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400">Password strength:</span>
                  <span className={`font-medium ${passwordStrength.color}`}>{passwordStrength.label}</span>
                </div>
                <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${passwordStrength.bg} transition-all duration-300`}
                    style={{ width: `${(Object.values(passwordChecks).filter(Boolean).length / 5) * 100}%` }}
                  />
                </div>
                <div className="grid grid-cols-2 gap-1 text-xs">
                  {[
                    { key: 'length', label: '8+ characters' },
                    { key: 'uppercase', label: 'Uppercase' },
                    { key: 'lowercase', label: 'Lowercase' },
                    { key: 'digit', label: 'Digit' },
                    { key: 'special', label: 'Special char' },
                  ].map(({ key, label }) => (
                    <div key={key} className="flex items-center gap-1">
                      {passwordChecks[key] ? (
                        <FiCheck className="w-3 h-3 text-green-400" />
                      ) : (
                        <FiX className="w-3 h-3 text-slate-500" />
                      )}
                      <span className={passwordChecks[key] ? 'text-slate-300' : 'text-slate-500'}>{label}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:from-cyan-800 disabled:to-blue-800 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-all duration-200 flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20"
            >
              {loading ? (
                <>
                  <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  {isRegister ? 'Creating account...' : 'Signing in...'}
                </>
              ) : (
                <>
                  <FiLock className="w-4 h-4" />
                  {isRegister ? 'Create Account' : 'Sign In'}
                </>
              )}
            </button>
          </form>

          <div className="mt-6 pt-5 border-t border-slate-700/50 text-center">
            {isRegister ? (
              <button
                onClick={toggleMode}
                className="text-cyan-400 hover:text-cyan-300 text-sm transition-colors font-medium"
              >
                Already have an account? Sign in
              </button>
            ) : (
              <button
                onClick={() => { setIsRegister(true); setLoginType('user'); }}
                className="text-cyan-400 hover:text-cyan-300 text-sm transition-colors font-medium"
              >
                {"Don't have an account? Register"}
              </button>
            )}
          </div>
        </div>

        <p className="text-center text-slate-600 text-xs mt-6">
          Protected by Advanced Threat Detection Engine
        </p>
      </div>
    </div>
  );
}
