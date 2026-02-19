import { useState, useEffect, useCallback, type ReactNode } from 'react';
import {
  AuthContext,
  type User,
  getStoredToken,
  setStoredToken,
  setStoredUser,
  getStoredUser,
  clearAuthStorage,
} from '@/lib/auth';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(getStoredUser());
  const [token, setToken] = useState<string | null>(getStoredToken());
  const [isLoading, setIsLoading] = useState(true);

  const isAuthenticated = !!user && !!token;

  const refreshUser = useCallback(async () => {
    const storedToken = getStoredToken();
    if (!storedToken) {
      setUser(null);
      setToken(null);
      setIsLoading(false);
      return;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/auth/me`, {
        headers: { Authorization: `Bearer ${storedToken}` },
      });

      if (response.ok) {
        const userData = await response.json();
        setUser(userData);
        setToken(storedToken);
        setStoredUser(userData);
      } else {
        // Token invalid or expired
        clearAuthStorage();
        setUser(null);
        setToken(null);
      }
    } catch {
      // Network error - keep stored state but don't clear (might be offline)
      const storedUser = getStoredUser();
      if (storedUser) {
        setUser(storedUser);
        setToken(storedToken);
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshUser();
  }, [refreshUser]);

  const login = useCallback(async (email: string, password: string) => {
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Login failed' }));
      throw new Error(error.error || 'Login failed');
    }

    const data = await response.json();
    setToken(data.token);
    setUser(data.user);
    setStoredToken(data.token);
    setStoredUser(data.user);
  }, []);

  const logout = useCallback(async () => {
    const storedToken = getStoredToken();
    if (storedToken) {
      try {
        await fetch(`${API_BASE_URL}/auth/logout`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${storedToken}` },
        });
      } catch {
        // Ignore logout API errors
      }
    }

    clearAuthStorage();
    setUser(null);
    setToken(null);
  }, []);

  return (
    <AuthContext.Provider
      value={{ user, token, isAuthenticated, isLoading, login, logout, refreshUser }}
    >
      {children}
    </AuthContext.Provider>
  );
}
