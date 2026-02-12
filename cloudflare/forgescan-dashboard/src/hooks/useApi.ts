import { useState, useEffect, useCallback } from 'react';
import { ApiError } from '@/lib/api';

interface UseApiState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
}

interface UseApiOptions {
  immediate?: boolean;
}

export function useApi<T>(
  apiCall: () => Promise<T>,
  options: UseApiOptions = { immediate: true }
) {
  const [state, setState] = useState<UseApiState<T>>({
    data: null,
    loading: options.immediate ?? true,
    error: null,
  });

  const execute = useCallback(async () => {
    setState((prev) => ({ ...prev, loading: true, error: null }));
    try {
      const data = await apiCall();
      setState({ data, loading: false, error: null });
      return data;
    } catch (err) {
      const errorMessage =
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : 'An unexpected error occurred';
      setState((prev) => ({ ...prev, loading: false, error: errorMessage }));
      throw err;
    }
  }, [apiCall]);

  useEffect(() => {
    if (options.immediate) {
      execute();
    }
  }, [execute, options.immediate]);

  const refetch = useCallback(() => {
    return execute();
  }, [execute]);

  return {
    ...state,
    refetch,
    execute,
  };
}

export function usePaginatedApi<T>(
  apiCall: (page: number, pageSize: number) => Promise<{
    items: T[];
    total: number;
    page: number;
    page_size: number;
    total_pages: number;
  }>,
  initialPage: number = 1,
  initialPageSize: number = 20
) {
  const [page, setPage] = useState(initialPage);
  const [pageSize, setPageSize] = useState(initialPageSize);
  const [state, setState] = useState<{
    items: T[];
    total: number;
    totalPages: number;
    loading: boolean;
    error: string | null;
  }>({
    items: [],
    total: 0,
    totalPages: 0,
    loading: true,
    error: null,
  });

  const execute = useCallback(async () => {
    setState((prev) => ({ ...prev, loading: true, error: null }));
    try {
      const result = await apiCall(page, pageSize);
      setState({
        items: result.items,
        total: result.total,
        totalPages: result.total_pages,
        loading: false,
        error: null,
      });
    } catch (err) {
      const errorMessage =
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : 'An unexpected error occurred';
      setState((prev) => ({ ...prev, loading: false, error: errorMessage }));
    }
  }, [apiCall, page, pageSize]);

  useEffect(() => {
    execute();
  }, [execute]);

  return {
    ...state,
    page,
    pageSize,
    setPage,
    setPageSize,
    refetch: execute,
  };
}
