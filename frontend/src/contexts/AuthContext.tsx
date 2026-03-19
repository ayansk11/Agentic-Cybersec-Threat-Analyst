import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react';
import {
  login as apiLogin,
  register as apiRegister,
  refreshToken as apiRefresh,
  logout as apiLogout,
  fetchCurrentUser,
  type UserResponse,
} from '../api/client';

interface AuthContextValue {
  user: UserResponse | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  oauthLogin: (provider: 'google' | 'github') => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Check for existing session on mount
  useEffect(() => {
    const init = async () => {
      // Try fetching current user (httpOnly cookie sent automatically)
      try {
        const me = await fetchCurrentUser();
        setUser(me);
        setIsLoading(false);
        return;
      } catch {
        // Token invalid or missing, try refresh
      }

      try {
        await apiRefresh();
        const me = await fetchCurrentUser();
        setUser(me);
      } catch {
        // Not authenticated
      }
      setIsLoading(false);
    };
    init();
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const data = await apiLogin(email, password);
    setUser(data.user);
  }, []);

  const register = useCallback(async (email: string, username: string, password: string) => {
    const data = await apiRegister(email, username, password);
    setUser(data.user);
  }, []);

  const logout = useCallback(async () => {
    try {
      await apiLogout();
    } catch {
      // Ignore errors on logout
    }
    setUser(null);
  }, []);

  const oauthLogin = useCallback((provider: 'google' | 'github') => {
    window.location.href = `/api/auth/oauth/${provider}/login`;
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        register,
        logout,
        oauthLogin,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
