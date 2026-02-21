import { useState, useEffect, useCallback, useRef } from 'react';
import { ApiError } from '@/lib/api';

interface UsePollingApiState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
}

interface UsePollingApiOptions {
  /** Polling interval in milliseconds (default: 5000) */
  interval?: number;
  /** Whether polling is enabled (default: true) */
  enabled?: boolean;
  /** Whether to fetch immediately on mount (default: true) */
  immediate?: boolean;
  /** Callback fired when data changes between polls */
  onDataChange?: () => void;
}

interface UsePollingApiReturn<T> extends UsePollingApiState<T> {
  /** Whether the hook is actively polling */
  isPolling: boolean;
  /** Timestamp of the last successful data fetch */
  lastUpdated: Date | null;
  /** Manually trigger a refetch */
  refetch: () => Promise<void>;
}

export function usePollingApi<T>(
  apiCall: () => Promise<T>,
  options: UsePollingApiOptions = {}
): UsePollingApiReturn<T> {
  const {
    interval = 5000,
    enabled = true,
    immediate = true,
    onDataChange,
  } = options;

  const [state, setState] = useState<UsePollingApiState<T>>({
    data: null,
    loading: true,
    error: null,
  });

  const [isPolling, setIsPolling] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  // Refs for stable references across renders
  const previousDataRef = useRef<string | null>(null);
  const onDataChangeRef = useRef(onDataChange);
  const intervalIdRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const isMountedRef = useRef(true);
  const isFirstFetchRef = useRef(true);
  const apiCallRef = useRef(apiCall);

  // Keep refs up to date
  onDataChangeRef.current = onDataChange;
  apiCallRef.current = apiCall;

  const fetchData = useCallback(async (isInitial: boolean = false) => {
    // Only show loading spinner on initial fetch, not during polling
    if (isInitial) {
      setState((prev) => ({ ...prev, loading: true, error: null }));
    }

    try {
      const result = await apiCallRef.current();

      if (!isMountedRef.current) return;

      const serialized = JSON.stringify(result);
      const hasChanged = previousDataRef.current !== null && previousDataRef.current !== serialized;

      previousDataRef.current = serialized;

      setState({
        data: result,
        loading: false,
        error: null,
      });
      setLastUpdated(new Date());

      // Fire change callback if data has changed (not on first fetch)
      if (hasChanged && onDataChangeRef.current) {
        onDataChangeRef.current();
      }
    } catch (error) {
      if (!isMountedRef.current) return;

      // During polling, keep previous data on error (don't flash error state)
      if (!isInitial && previousDataRef.current !== null) {
        // Silently ignore polling errors when we have existing data
        return;
      }

      let errorMessage = 'An unexpected error occurred';
      if (error instanceof ApiError) {
        errorMessage = error.message;
      } else if (error instanceof Error) {
        errorMessage = error.message;
      }

      setState((prev) => ({
        ...prev,
        loading: false,
        error: errorMessage,
      }));
    }
  }, []); // Stable - uses refs internally

  const refetch = useCallback(async () => {
    await fetchData(false);
  }, [fetchData]);

  // Initial fetch
  useEffect(() => {
    if (immediate && enabled && isFirstFetchRef.current) {
      isFirstFetchRef.current = false;
      fetchData(true);
    }
  }, [immediate, enabled, fetchData]);

  // Polling interval management
  useEffect(() => {
    if (!enabled) {
      // Stop polling when disabled
      if (intervalIdRef.current) {
        clearInterval(intervalIdRef.current);
        intervalIdRef.current = null;
      }
      setIsPolling(false);
      return;
    }

    // Start polling
    setIsPolling(true);
    intervalIdRef.current = setInterval(() => {
      fetchData(false);
    }, interval);

    return () => {
      if (intervalIdRef.current) {
        clearInterval(intervalIdRef.current);
        intervalIdRef.current = null;
      }
      setIsPolling(false);
    };
  }, [enabled, interval, fetchData]);

  // Tab visibility: pause polling when tab is hidden, refetch when visible
  useEffect(() => {
    if (!enabled) return;

    const handleVisibilityChange = () => {
      if (document.hidden) {
        // Pause polling
        if (intervalIdRef.current) {
          clearInterval(intervalIdRef.current);
          intervalIdRef.current = null;
        }
        setIsPolling(false);
      } else {
        // Resume: immediate refetch + restart interval
        fetchData(false);
        intervalIdRef.current = setInterval(() => {
          fetchData(false);
        }, interval);
        setIsPolling(true);
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [enabled, interval, fetchData]);

  // Cleanup on unmount
  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
      if (intervalIdRef.current) {
        clearInterval(intervalIdRef.current);
        intervalIdRef.current = null;
      }
    };
  }, []);

  return {
    ...state,
    isPolling,
    lastUpdated,
    refetch,
  };
}
