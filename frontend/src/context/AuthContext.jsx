import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { authAPI } from '../services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('token');
    const savedUser = localStorage.getItem('user');
    if (token && savedUser) {
      try {
        setUser(JSON.parse(savedUser));
      } catch {
        localStorage.removeItem('token');
        localStorage.removeItem('refreshToken');
        localStorage.removeItem('user');
      }
    }
    setLoading(false);
  }, []);

  const refreshAccessToken = useCallback(async () => {
    const refreshToken = localStorage.getItem('refreshToken');
    if (!refreshToken) {
      logout();
      return null;
    }
    try {
      const res = await authAPI.refresh(refreshToken);
      const { access_token, refresh_token: newRefreshToken, user: userData } = res.data;
      localStorage.setItem('token', access_token);
      if (newRefreshToken) {
        localStorage.setItem('refreshToken', newRefreshToken);
      }
      if (userData) {
        localStorage.setItem('user', JSON.stringify(userData));
        setUser(userData);
      }
      return access_token;
    } catch {
      logout();
      return null;
    }
  }, []);

  const login = async (username, password) => {
    const res = await authAPI.login(username, password);
    const { access_token, refresh_token, user: userData } = res.data;
    localStorage.setItem('token', access_token);
    if (refresh_token) {
      localStorage.setItem('refreshToken', refresh_token);
    }
    localStorage.setItem('user', JSON.stringify(userData));
    setUser(userData);
    return userData;
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('user');
    setUser(null);
  };

  const isAdmin = user?.role === 'ADMIN' || user?.is_admin === true;
  const isUser = user?.role === 'USER';

  return (
    <AuthContext.Provider value={{ user, login, logout, loading, refreshAccessToken, isAdmin, isUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
