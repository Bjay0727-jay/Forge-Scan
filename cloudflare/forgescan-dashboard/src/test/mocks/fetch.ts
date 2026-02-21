import { vi } from 'vitest';

/**
 * Creates a mock fetch that maps URL patterns to responses.
 * Each handler receives the Request and returns a Response-like object.
 */
interface MockResponse {
  status?: number;
  body?: unknown;
  headers?: Record<string, string>;
}

type MockHandler = (url: string, init?: RequestInit) => MockResponse;

/**
 * Set up a global fetch mock that routes requests through handlers.
 * Handlers are matched by substring against the URL.
 * Returns the mock function for assertions.
 */
export function mockFetch(handlers: Record<string, MockHandler | MockResponse> = {}) {
  const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

    // Find matching handler by URL substring
    for (const [pattern, handler] of Object.entries(handlers)) {
      if (url.includes(pattern)) {
        const result = typeof handler === 'function' ? handler(url, init) : handler;
        const status = result.status ?? 200;
        const body = result.body !== undefined ? JSON.stringify(result.body) : '';

        return new Response(body, {
          status,
          statusText: status === 200 ? 'OK' : `Error ${status}`,
          headers: { 'Content-Type': 'application/json', ...result.headers },
        });
      }
    }

    // Default: 404 if no handler matches
    return new Response(JSON.stringify({ error: 'Not found' }), {
      status: 404,
      statusText: 'Not Found',
      headers: { 'Content-Type': 'application/json' },
    });
  });

  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

/**
 * Create a mock fetch that always returns the same response.
 */
export function mockFetchOnce(body: unknown, status = 200) {
  return mockFetch({
    '': { status, body },
  });
}

/**
 * Create a mock fetch that rejects with a network error.
 */
export function mockFetchError(message = 'Network error') {
  const fetchMock = vi.fn().mockRejectedValue(new TypeError(message));
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}
