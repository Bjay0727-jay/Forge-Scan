import { describe, it, expect, vi } from 'vitest';
import { renderHook } from '@testing-library/react';
import {
  getStoredToken,
  setStoredToken,
  getStoredUser,
  setStoredUser,
  clearAuthStorage,
  hasRole,
  useAuth,
  type User,
} from './auth';

// --- getStoredToken ---

describe('getStoredToken', () => {
  it('returns null when no token is stored', () => {
    expect(getStoredToken()).toBeNull();
  });

  it('returns the stored token string', () => {
    localStorage.setItem('forgescan_token', 'test-jwt-token');
    expect(getStoredToken()).toBe('test-jwt-token');
  });
});

// --- setStoredToken ---

describe('setStoredToken', () => {
  it('stores token in localStorage under forgescan_token', () => {
    setStoredToken('my-token');
    expect(localStorage.getItem('forgescan_token')).toBe('my-token');
  });

  it('overwrites existing token', () => {
    setStoredToken('old-token');
    setStoredToken('new-token');
    expect(localStorage.getItem('forgescan_token')).toBe('new-token');
  });
});

// --- getStoredUser ---

describe('getStoredUser', () => {
  it('returns null when no user is stored', () => {
    expect(getStoredUser()).toBeNull();
  });

  it('returns parsed User object from localStorage', () => {
    const user: User = {
      id: 'user-1',
      email: 'test@example.com',
      display_name: 'Test User',
      role: 'platform_admin',
    };
    localStorage.setItem('forgescan_user', JSON.stringify(user));
    expect(getStoredUser()).toEqual(user);
  });

  it('returns null when stored value is invalid JSON', () => {
    localStorage.setItem('forgescan_user', 'not-json{{');
    expect(getStoredUser()).toBeNull();
  });
});

// --- setStoredUser ---

describe('setStoredUser', () => {
  it('stores JSON-serialized user in localStorage under forgescan_user', () => {
    const user: User = {
      id: 'user-2',
      email: 'admin@example.com',
      display_name: 'Admin',
      role: 'scan_admin',
    };
    setStoredUser(user);
    const stored = JSON.parse(localStorage.getItem('forgescan_user')!);
    expect(stored.id).toBe('user-2');
    expect(stored.email).toBe('admin@example.com');
  });
});

// --- clearAuthStorage ---

describe('clearAuthStorage', () => {
  it('removes both token and user from localStorage', () => {
    localStorage.setItem('forgescan_token', 'token');
    localStorage.setItem('forgescan_user', '{}');
    clearAuthStorage();
    expect(localStorage.getItem('forgescan_token')).toBeNull();
    expect(localStorage.getItem('forgescan_user')).toBeNull();
  });
});

// --- hasRole ---

describe('hasRole', () => {
  it('returns false for null user', () => {
    expect(hasRole(null, 'scan_admin')).toBe(false);
  });

  it('returns true for platform_admin regardless of role list', () => {
    const admin: User = {
      id: '1',
      email: 'a@b.com',
      display_name: 'Admin',
      role: 'platform_admin',
    };
    expect(hasRole(admin, 'scan_admin')).toBe(true);
    expect(hasRole(admin, 'vuln_manager', 'auditor')).toBe(true);
  });

  it('returns true when user role is in the allowed roles', () => {
    const user: User = {
      id: '2',
      email: 'b@c.com',
      display_name: 'Scanner',
      role: 'scan_admin',
    };
    expect(hasRole(user, 'scan_admin', 'vuln_manager')).toBe(true);
  });

  it('returns false when user role is not in the allowed roles', () => {
    const user: User = {
      id: '3',
      email: 'c@d.com',
      display_name: 'Viewer',
      role: 'auditor',
    };
    expect(hasRole(user, 'scan_admin', 'vuln_manager')).toBe(false);
  });

  it('handles empty roles argument', () => {
    const user: User = {
      id: '4',
      email: 'd@e.com',
      display_name: 'Test',
      role: 'scan_admin',
    };
    expect(hasRole(user)).toBe(false);
  });
});

// --- useAuth ---

describe('useAuth', () => {
  it('throws when used outside AuthProvider', () => {
    // Suppress console.error for the expected error
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => {
      renderHook(() => useAuth());
    }).toThrow('useAuth must be used within an AuthProvider');

    consoleSpy.mockRestore();
  });
});
