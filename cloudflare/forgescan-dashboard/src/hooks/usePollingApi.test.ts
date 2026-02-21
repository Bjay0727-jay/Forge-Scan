import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import { usePollingApi } from './usePollingApi';

describe('usePollingApi', () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('fetches data immediately by default', async () => {
    const mockData = { items: [{ id: '1' }], has_active: true };
    const apiCall = vi.fn().mockResolvedValue(mockData);

    const { result } = renderHook(() =>
      usePollingApi(apiCall, { interval: 5000, enabled: true })
    );

    // Initially loading
    expect(result.current.loading).toBe(true);
    expect(result.current.data).toBeNull();

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.data).toEqual(mockData);
    expect(apiCall).toHaveBeenCalledTimes(1);
  });

  it('does not fetch immediately when immediate is false', async () => {
    const apiCall = vi.fn().mockResolvedValue({ items: [] });

    renderHook(() =>
      usePollingApi(apiCall, { interval: 5000, immediate: false })
    );

    // Should not call the API immediately
    expect(apiCall).not.toHaveBeenCalled();
  });

  it('polls at the specified interval', async () => {
    const mockData = { items: [], has_active: false };
    const apiCall = vi.fn().mockResolvedValue(mockData);

    const { result } = renderHook(() =>
      usePollingApi(apiCall, { interval: 3000, enabled: true })
    );

    // Wait for initial fetch
    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });
    expect(apiCall).toHaveBeenCalledTimes(1);

    // Advance timer to trigger poll
    await act(async () => {
      vi.advanceTimersByTime(3000);
    });

    await waitFor(() => {
      expect(apiCall).toHaveBeenCalledTimes(2);
    });

    // Advance again
    await act(async () => {
      vi.advanceTimersByTime(3000);
    });

    await waitFor(() => {
      expect(apiCall).toHaveBeenCalledTimes(3);
    });
  });

  it('does not poll when enabled is false', async () => {
    const apiCall = vi.fn().mockResolvedValue({ items: [] });

    renderHook(() =>
      usePollingApi(apiCall, { interval: 3000, enabled: false })
    );

    // Should not call at all when disabled
    expect(apiCall).not.toHaveBeenCalled();

    // Advance time — still should not call
    await act(async () => {
      vi.advanceTimersByTime(10000);
    });

    expect(apiCall).not.toHaveBeenCalled();
  });

  it('shows loading only on initial fetch (silent polling)', async () => {
    let callCount = 0;
    const apiCall = vi.fn().mockImplementation(() => {
      callCount++;
      return Promise.resolve({ items: [{ id: String(callCount) }] });
    });

    const { result } = renderHook(() =>
      usePollingApi(apiCall, { interval: 3000, enabled: true })
    );

    // First fetch shows loading
    expect(result.current.loading).toBe(true);

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    // Trigger poll
    await act(async () => {
      vi.advanceTimersByTime(3000);
    });

    // Should NOT show loading during poll
    expect(result.current.loading).toBe(false);

    await waitFor(() => {
      expect(apiCall).toHaveBeenCalledTimes(2);
    });

    // Still not loading
    expect(result.current.loading).toBe(false);
  });

  it('fires onDataChange when data changes', async () => {
    let callCount = 0;
    const apiCall = vi.fn().mockImplementation(() => {
      callCount++;
      return Promise.resolve({ items: [{ id: String(callCount) }], count: callCount });
    });
    const onDataChange = vi.fn();

    const { result } = renderHook(() =>
      usePollingApi(apiCall, {
        interval: 3000,
        enabled: true,
        onDataChange,
      })
    );

    // Wait for initial fetch
    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    // onDataChange should NOT fire on first fetch
    expect(onDataChange).not.toHaveBeenCalled();

    // Trigger poll - data will change (count goes from 1 to 2)
    await act(async () => {
      vi.advanceTimersByTime(3000);
    });

    await waitFor(() => {
      expect(onDataChange).toHaveBeenCalledTimes(1);
    });
  });

  it('does not fire onDataChange when data is the same', async () => {
    const staticData = { items: [{ id: '1' }], has_active: true };
    const apiCall = vi.fn().mockResolvedValue(staticData);
    const onDataChange = vi.fn();

    const { result } = renderHook(() =>
      usePollingApi(apiCall, {
        interval: 3000,
        enabled: true,
        onDataChange,
      })
    );

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    // Trigger poll — same data
    await act(async () => {
      vi.advanceTimersByTime(3000);
    });

    await waitFor(() => {
      expect(apiCall).toHaveBeenCalledTimes(2);
    });

    // onDataChange should NOT fire when data is the same
    expect(onDataChange).not.toHaveBeenCalled();
  });

  it('keeps previous data on polling error', async () => {
    const goodData = { items: [{ id: '1' }] };
    let callCount = 0;
    const apiCall = vi.fn().mockImplementation(() => {
      callCount++;
      if (callCount === 1) return Promise.resolve(goodData);
      return Promise.reject(new Error('Network error'));
    });

    const { result } = renderHook(() =>
      usePollingApi(apiCall, { interval: 3000, enabled: true })
    );

    await waitFor(() => {
      expect(result.current.data).toEqual(goodData);
    });

    // Trigger poll — will error
    await act(async () => {
      vi.advanceTimersByTime(3000);
    });

    await waitFor(() => {
      expect(apiCall).toHaveBeenCalledTimes(2);
    });

    // Data should still be the good data, not null
    expect(result.current.data).toEqual(goodData);
    expect(result.current.error).toBeNull();
  });

  it('cleans up interval on unmount', async () => {
    const apiCall = vi.fn().mockResolvedValue({ items: [] });

    const { result, unmount } = renderHook(() =>
      usePollingApi(apiCall, { interval: 3000, enabled: true })
    );

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    unmount();

    // Advance time — should not call API after unmount
    await act(async () => {
      vi.advanceTimersByTime(10000);
    });

    // Should only have been called once (initial fetch)
    expect(apiCall).toHaveBeenCalledTimes(1);
  });

  it('supports manual refetch', async () => {
    const apiCall = vi.fn().mockResolvedValue({ items: [] });

    const { result } = renderHook(() =>
      usePollingApi(apiCall, { interval: 5000, enabled: true })
    );

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(apiCall).toHaveBeenCalledTimes(1);

    // Manual refetch
    await act(async () => {
      await result.current.refetch();
    });

    expect(apiCall).toHaveBeenCalledTimes(2);
  });

  it('sets lastUpdated after successful fetch', async () => {
    const apiCall = vi.fn().mockResolvedValue({ items: [] });

    const { result } = renderHook(() =>
      usePollingApi(apiCall, { interval: 5000, enabled: true })
    );

    expect(result.current.lastUpdated).toBeNull();

    await waitFor(() => {
      expect(result.current.lastUpdated).not.toBeNull();
    });

    expect(result.current.lastUpdated).toBeInstanceOf(Date);
  });

  it('reports isPolling state correctly', async () => {
    const apiCall = vi.fn().mockResolvedValue({ items: [] });

    const { result, rerender } = renderHook(
      ({ enabled }) => usePollingApi(apiCall, { interval: 5000, enabled }),
      { initialProps: { enabled: true } }
    );

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.isPolling).toBe(true);

    // Disable polling
    rerender({ enabled: false });

    await waitFor(() => {
      expect(result.current.isPolling).toBe(false);
    });
  });

  it('handles initial fetch error correctly', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const apiCall = vi.fn().mockRejectedValue(new Error('Server down'));

    const { result } = renderHook(() =>
      usePollingApi(apiCall, { interval: 5000, enabled: true })
    );

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.error).toBe('Server down');
    expect(result.current.data).toBeNull();
  });
});
