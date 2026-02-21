import { describe, it, expect, vi, afterEach } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import { useApi, usePaginatedApi } from './useApi';

// Suppress console.error for expected hook errors
const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

afterEach(() => {
  vi.unstubAllGlobals();
  consoleSpy.mockClear();
});

// --- useApi ---

describe('useApi', () => {
  it('starts with loading: true when immediate (default)', () => {
    const apiCall = vi.fn().mockResolvedValue({ id: '1' });
    const { result } = renderHook(() => useApi(apiCall));
    expect(result.current.loading).toBe(true);
  });

  it('starts with loading: false when immediate is false', () => {
    const apiCall = vi.fn().mockResolvedValue({ id: '1' });
    const { result } = renderHook(() => useApi(apiCall, { immediate: false }));
    expect(result.current.loading).toBe(false);
    expect(result.current.data).toBeNull();
  });

  it('sets data on successful call', async () => {
    const apiCall = vi.fn().mockResolvedValue({ id: '1', name: 'Test' });
    const { result } = renderHook(() => useApi(apiCall));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.data).toEqual({ id: '1', name: 'Test' });
    expect(result.current.error).toBeNull();
  });

  it('sets error on failed call', async () => {
    // Use immediate: false to avoid unhandled rejection from useEffect
    // (the hook re-throws errors from execute(), and useEffect has no .catch)
    const apiCall = vi.fn().mockRejectedValue(new Error('Network failure'));
    const { result } = renderHook(() => useApi(apiCall, { immediate: false }));

    await act(async () => {
      try {
        await result.current.execute();
      } catch {
        // expected
      }
    });

    expect(result.current.error).toBe('Network failure');
    expect(result.current.data).toBeNull();
    expect(result.current.loading).toBe(false);
  });

  it('execute() triggers the API call manually', async () => {
    const apiCall = vi.fn().mockResolvedValue({ count: 42 });
    const { result } = renderHook(() => useApi(apiCall, { immediate: false }));

    expect(apiCall).not.toHaveBeenCalled();

    await act(async () => {
      await result.current.execute();
    });

    expect(apiCall).toHaveBeenCalledTimes(1);
    expect(result.current.data).toEqual({ count: 42 });
  });

  it('refetch() re-triggers the API call', async () => {
    let callCount = 0;
    const apiCall = vi.fn().mockImplementation(() => {
      callCount++;
      return Promise.resolve({ call: callCount });
    });

    const { result } = renderHook(() => useApi(apiCall));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.data).toEqual({ call: 1 });

    await act(async () => {
      await result.current.refetch();
    });

    expect(result.current.data).toEqual({ call: 2 });
    expect(apiCall).toHaveBeenCalledTimes(2);
  });

  it('clears previous error on new execute', async () => {
    let shouldFail = true;
    const apiCall = vi.fn().mockImplementation(() => {
      if (shouldFail) return Promise.reject(new Error('fail'));
      return Promise.resolve({ ok: true });
    });

    // Use immediate: false to control execution flow and avoid unhandled rejections
    const { result } = renderHook(() => useApi(apiCall, { immediate: false }));

    // First call — fails
    await act(async () => {
      try {
        await result.current.execute();
      } catch {
        // expected
      }
    });

    expect(result.current.error).toBe('fail');

    // Second call — succeeds
    shouldFail = false;
    await act(async () => {
      await result.current.refetch();
    });

    expect(result.current.error).toBeNull();
    expect(result.current.data).toEqual({ ok: true });
  });

  it('execute() re-throws the error', async () => {
    const apiCall = vi.fn().mockRejectedValue(new Error('boom'));
    const { result } = renderHook(() => useApi(apiCall, { immediate: false }));

    await act(async () => {
      await expect(result.current.execute()).rejects.toThrow('boom');
    });
  });

  it('data is initially null', () => {
    const apiCall = vi.fn().mockResolvedValue({ foo: 'bar' });
    const { result } = renderHook(() => useApi(apiCall, { immediate: false }));
    expect(result.current.data).toBeNull();
    expect(result.current.error).toBeNull();
  });
});

// --- usePaginatedApi ---

describe('usePaginatedApi', () => {
  const makePaginatedResponse = (items: unknown[], page = 1, total = 50, totalPages = 3) => ({
    items,
    total,
    page,
    page_size: 20,
    total_pages: totalPages,
  });

  it('starts with loading: true', () => {
    const apiCall = vi.fn().mockResolvedValue(makePaginatedResponse([]));
    const { result } = renderHook(() => usePaginatedApi(apiCall));
    expect(result.current.loading).toBe(true);
  });

  it('sets items and pagination data on success', async () => {
    const items = [{ id: '1' }, { id: '2' }];
    const apiCall = vi.fn().mockResolvedValue(makePaginatedResponse(items, 1, 50, 3));
    const { result } = renderHook(() => usePaginatedApi(apiCall));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.items).toEqual(items);
    expect(result.current.total).toBe(50);
    expect(result.current.totalPages).toBe(3);
    expect(result.current.page).toBe(1);
    expect(result.current.error).toBeNull();
  });

  it('passes page and pageSize to API call', async () => {
    const apiCall = vi.fn().mockResolvedValue(makePaginatedResponse([]));
    renderHook(() => usePaginatedApi(apiCall, 2, 10));

    await waitFor(() => {
      expect(apiCall).toHaveBeenCalledWith(2, 10);
    });
  });

  it('refetches when page changes via setPage', async () => {
    const apiCall = vi.fn().mockResolvedValue(makePaginatedResponse([{ id: '1' }]));
    const { result } = renderHook(() => usePaginatedApi(apiCall));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    act(() => {
      result.current.setPage(2);
    });

    await waitFor(() => {
      expect(apiCall).toHaveBeenCalledWith(2, 20);
    });
  });

  it('handles errors gracefully', async () => {
    // usePaginatedApi does NOT re-throw — it catches and sets error state
    const apiCall = vi.fn().mockRejectedValue(new Error('Server error'));
    const { result } = renderHook(() => usePaginatedApi(apiCall));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.error).toBe('Server error');
    expect(result.current.items).toEqual([]);
  });

  it('refetch() re-triggers the API call', async () => {
    let callCount = 0;
    const apiCall = vi.fn().mockImplementation((page: number, _pageSize: number) => {
      callCount++;
      return Promise.resolve(makePaginatedResponse([{ call: callCount }], page));
    });

    const { result } = renderHook(() => usePaginatedApi(apiCall));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    await act(async () => {
      await result.current.refetch();
    });

    expect(apiCall).toHaveBeenCalledTimes(2);
  });

  it('exposes setPageSize', async () => {
    const apiCall = vi.fn().mockResolvedValue(makePaginatedResponse([]));
    const { result } = renderHook(() => usePaginatedApi(apiCall, 1, 20));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    act(() => {
      result.current.setPageSize(50);
    });

    await waitFor(() => {
      expect(apiCall).toHaveBeenCalledWith(1, 50);
    });
  });
});
