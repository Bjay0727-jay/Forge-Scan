/**
 * OpenAPI 3.1 specification for the ForgeScan 360 API.
 *
 * Served at GET /api/docs/openapi.json and rendered by the Swagger UI
 * page at GET /api/docs.
 */

export const openApiSpec = {
  openapi: '3.1.0',
  info: {
    title: 'ForgeScan 360 API',
    version: '1.0.0',
    description:
      'Vulnerability management platform API — scan, ingest, analyse, and remediate security findings across your infrastructure.',
    contact: { name: 'ForgeScan Team' },
    license: { name: 'Proprietary' },
  },
  servers: [
    {
      url: 'https://forgescan-api.stanley-riley.workers.dev',
      description: 'Production (Cloudflare Workers)',
    },
    { url: 'http://localhost:8787', description: 'Local development' },
  ],

  // ─── Security Schemes ──────────────────────────────────────────────────
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'JWT token obtained from POST /api/v1/auth/login',
      },
      apiKeyAuth: {
        type: 'apiKey',
        in: 'header',
        name: 'X-API-Key',
        description: 'API key created via POST /api/v1/auth/api-keys',
      },
      scannerKeyAuth: {
        type: 'apiKey',
        in: 'header',
        name: 'X-Scanner-Key',
        description: 'Scanner key from POST /api/v1/scanner/register',
      },
    },

    // ─── Reusable Schemas ──────────────────────────────────────────────
    schemas: {
      // ── Error ───────────────────────────────────────────────────────
      ErrorResponse: {
        type: 'object',
        properties: {
          error: {
            type: 'object',
            properties: {
              code: { type: 'string', example: 'VALIDATION_ERROR' },
              message: { type: 'string', example: 'Missing required field: title' },
              details: { type: 'object', additionalProperties: true },
            },
            required: ['code', 'message'],
          },
        },
        required: ['error'],
      },

      // ── Pagination ──────────────────────────────────────────────────
      PagePagination: {
        type: 'object',
        properties: {
          total: { type: 'integer' },
          page: { type: 'integer' },
          page_size: { type: 'integer' },
          total_pages: { type: 'integer' },
        },
      },

      // ── Auth ────────────────────────────────────────────────────────
      User: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          email: { type: 'string', format: 'email' },
          display_name: { type: 'string' },
          role: {
            type: 'string',
            enum: ['platform_admin', 'scan_admin', 'vuln_manager', 'remediation_owner', 'auditor'],
          },
          is_active: { type: 'integer', enum: [0, 1] },
          last_login_at: { type: 'string', format: 'date-time', nullable: true },
          created_at: { type: 'string', format: 'date-time' },
          updated_at: { type: 'string', format: 'date-time' },
        },
      },
      LoginRequest: {
        type: 'object',
        required: ['email', 'password'],
        properties: {
          email: { type: 'string', format: 'email' },
          password: { type: 'string', minLength: 8 },
        },
      },
      LoginResponse: {
        type: 'object',
        properties: {
          token: { type: 'string' },
          expires_at: { type: 'string', format: 'date-time' },
          user: { $ref: '#/components/schemas/User' },
        },
      },
      RegisterRequest: {
        type: 'object',
        required: ['email', 'password', 'display_name'],
        properties: {
          email: { type: 'string', format: 'email' },
          password: { type: 'string', minLength: 8 },
          display_name: { type: 'string' },
          role: { type: 'string', enum: ['platform_admin', 'scan_admin', 'vuln_manager', 'remediation_owner', 'auditor'] },
        },
      },

      // ── Asset ───────────────────────────────────────────────────────
      Asset: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          hostname: { type: 'string', nullable: true },
          fqdn: { type: 'string', nullable: true },
          ip_addresses: { type: 'string', description: 'JSON array of IPs' },
          mac_addresses: { type: 'string', nullable: true },
          os: { type: 'string', nullable: true },
          os_version: { type: 'string', nullable: true },
          asset_type: { type: 'string', enum: ['host', 'container', 'cloud', 'network', 'application'] },
          network_zone: { type: 'string', nullable: true },
          tags: { type: 'string', description: 'JSON array' },
          attributes: { type: 'string', description: 'JSON object' },
          risk_score: { type: 'number', nullable: true },
          first_seen: { type: 'string', format: 'date-time' },
          last_seen: { type: 'string', format: 'date-time' },
          created_at: { type: 'string', format: 'date-time' },
          updated_at: { type: 'string', format: 'date-time' },
        },
      },
      CreateAssetRequest: {
        type: 'object',
        properties: {
          hostname: { type: 'string' },
          fqdn: { type: 'string' },
          ip_addresses: { type: 'array', items: { type: 'string' } },
          mac_addresses: { type: 'array', items: { type: 'string' } },
          os: { type: 'string' },
          os_version: { type: 'string' },
          asset_type: { type: 'string' },
          network_zone: { type: 'string' },
          tags: { type: 'array', items: { type: 'string' } },
          attributes: { type: 'object' },
        },
      },

      // ── Finding ─────────────────────────────────────────────────────
      Finding: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          asset_id: { type: 'string', format: 'uuid', nullable: true },
          scan_id: { type: 'string', format: 'uuid', nullable: true },
          vulnerability_id: { type: 'string', nullable: true },
          vendor: { type: 'string' },
          vendor_id: { type: 'string', nullable: true },
          title: { type: 'string' },
          description: { type: 'string', nullable: true },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
          frs_score: { type: 'number', nullable: true },
          port: { type: 'integer', nullable: true },
          protocol: { type: 'string', nullable: true },
          service: { type: 'string', nullable: true },
          state: { type: 'string', enum: ['open', 'acknowledged', 'resolved', 'false_positive', 'reopened', 'fixed', 'accepted'] },
          solution: { type: 'string', nullable: true },
          evidence: { type: 'string', nullable: true },
          cve_id: { type: 'string', nullable: true },
          cvss_score: { type: 'number', nullable: true },
          affected_component: { type: 'string', nullable: true },
          remediation: { type: 'string', nullable: true },
          references: { type: 'string', nullable: true },
          metadata: { type: 'string', nullable: true },
          first_seen: { type: 'string', format: 'date-time' },
          last_seen: { type: 'string', format: 'date-time' },
          created_at: { type: 'string', format: 'date-time' },
          updated_at: { type: 'string', format: 'date-time' },
          fixed_at: { type: 'string', format: 'date-time', nullable: true },
        },
      },
      CreateFindingRequest: {
        type: 'object',
        required: ['vendor', 'vendor_id', 'title', 'severity'],
        properties: {
          asset_id: { type: 'string', format: 'uuid' },
          vulnerability_id: { type: 'string' },
          vendor: { type: 'string' },
          vendor_id: { type: 'string' },
          title: { type: 'string' },
          description: { type: 'string' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
          frs_score: { type: 'number' },
          port: { type: 'integer' },
          protocol: { type: 'string' },
          service: { type: 'string' },
          state: { type: 'string', default: 'open' },
          solution: { type: 'string' },
          evidence: { type: 'string' },
          metadata: { type: 'object' },
        },
      },

      // ── Scan ────────────────────────────────────────────────────────
      Scan: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          name: { type: 'string' },
          scan_type: { type: 'string', enum: ['network', 'container', 'cloud', 'web', 'code', 'compliance', 'webapp', 'config_audit', 'full'] },
          targets: { type: 'string', description: 'JSON array of targets' },
          config: { type: 'string', nullable: true },
          status: { type: 'string', enum: ['pending', 'running', 'completed', 'failed', 'cancelled'] },
          findings_count: { type: 'integer' },
          assets_count: { type: 'integer' },
          error_message: { type: 'string', nullable: true },
          started_at: { type: 'string', format: 'date-time', nullable: true },
          completed_at: { type: 'string', format: 'date-time', nullable: true },
          created_at: { type: 'string', format: 'date-time' },
          updated_at: { type: 'string', format: 'date-time' },
        },
      },
      CreateScanRequest: {
        type: 'object',
        required: ['name', 'type'],
        properties: {
          name: { type: 'string' },
          type: { type: 'string', enum: ['network', 'container', 'cloud', 'web', 'code', 'compliance', 'webapp', 'config_audit', 'full'] },
          targets: { type: 'array', items: { type: 'string' } },
          configuration: { type: 'object' },
        },
      },

      // ── Ingestion Job ───────────────────────────────────────────────
      IngestionJob: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          vendor: { type: 'string' },
          source: { type: 'string' },
          status: { type: 'string', enum: ['processing', 'completed', 'failed'] },
          records_processed: { type: 'integer' },
          records_imported: { type: 'integer' },
          records_skipped: { type: 'integer' },
          errors: { type: 'string', nullable: true, description: 'JSON array of error strings' },
          started_at: { type: 'string', format: 'date-time' },
          completed_at: { type: 'string', format: 'date-time', nullable: true },
        },
      },
      UploadResponse: {
        type: 'object',
        properties: {
          job_id: { type: 'string', format: 'uuid' },
          type: { type: 'string', enum: ['findings', 'assets'] },
          status: { type: 'string', enum: ['completed', 'failed'] },
          records_processed: { type: 'integer' },
          records_imported: { type: 'integer' },
          records_skipped: { type: 'integer' },
          errors: { type: 'array', items: { type: 'string' } },
        },
      },

      // ── Vulnerability ───────────────────────────────────────────────
      Vulnerability: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          cve_id: { type: 'string', pattern: '^CVE-\\d{4}-\\d{4,}$' },
          title: { type: 'string', nullable: true },
          description: { type: 'string', nullable: true },
          cvss_score: { type: 'number', nullable: true },
          cvss_vector: { type: 'string', nullable: true },
          cvss_version: { type: 'string', default: '3.1' },
          epss_score: { type: 'number', nullable: true },
          epss_percentile: { type: 'number', nullable: true },
          in_kev: { type: 'integer', enum: [0, 1] },
          severity: { type: 'string', nullable: true },
          published_at: { type: 'string', format: 'date-time', nullable: true },
          modified_at: { type: 'string', format: 'date-time', nullable: true },
          created_at: { type: 'string', format: 'date-time' },
          updated_at: { type: 'string', format: 'date-time' },
        },
      },

      // ── Dashboard ───────────────────────────────────────────────────
      DashboardOverview: {
        type: 'object',
        properties: {
          totals: {
            type: 'object',
            properties: {
              total_assets: { type: 'integer' },
              open_findings: { type: 'integer' },
              fixed_findings: { type: 'integer' },
              completed_scans: { type: 'integer' },
            },
          },
          severity_breakdown: { type: 'array', items: { type: 'object', properties: { severity: { type: 'string' }, count: { type: 'integer' } } } },
          recent_findings: { type: 'array', items: { $ref: '#/components/schemas/Finding' } },
          top_vulnerable_assets: { type: 'array', items: { type: 'object' } },
          generated_at: { type: 'string', format: 'date-time' },
        },
      },

      // ── Report ──────────────────────────────────────────────────────
      ExecutiveSummary: {
        type: 'object',
        properties: {
          generated_at: { type: 'string', format: 'date-time' },
          period: {
            type: 'object',
            properties: {
              start: { type: 'string', format: 'date-time' },
              end: { type: 'string', format: 'date-time' },
            },
          },
          totals: {
            type: 'object',
            properties: {
              assets: { type: 'integer' },
              open_findings: { type: 'integer' },
              fixed_findings: { type: 'integer' },
              new_findings_period: { type: 'integer' },
              remediation_rate: { type: 'number' },
            },
          },
          risk_score: {
            type: 'object',
            properties: { current: { type: 'number' }, grade: { type: 'string', enum: ['A', 'B', 'C', 'D', 'F'] } },
          },
          severity_breakdown: { type: 'array', items: { type: 'object', properties: { severity: { type: 'string' }, count: { type: 'integer' } } } },
          top_risks: { type: 'array', items: { type: 'object' } },
          recommendations: { type: 'array', items: { type: 'string' } },
        },
      },
    },

    // ─── Reusable Parameters ────────────────────────────────────────
    parameters: {
      page: { name: 'page', in: 'query', schema: { type: 'integer', minimum: 1, default: 1 } },
      pageSize: { name: 'page_size', in: 'query', schema: { type: 'integer', minimum: 1, maximum: 100, default: 20 } },
      sortOrder: { name: 'sort_order', in: 'query', schema: { type: 'string', enum: ['asc', 'desc'], default: 'desc' } },
      limit: { name: 'limit', in: 'query', schema: { type: 'integer', minimum: 1, default: 50 } },
      offset: { name: 'offset', in: 'query', schema: { type: 'integer', minimum: 0, default: 0 } },
    },
  },

  security: [{ bearerAuth: [] }, { apiKeyAuth: [] }],

  tags: [
    { name: 'Health', description: 'Health check endpoints' },
    { name: 'Auth', description: 'Authentication, users, sessions, and API keys' },
    { name: 'Assets', description: 'IT asset inventory management' },
    { name: 'Findings', description: 'Vulnerability findings CRUD and statistics' },
    { name: 'Scans', description: 'Scan lifecycle management' },
    { name: 'Dashboard', description: 'Aggregated metrics and visualisation data' },
    { name: 'Ingest', description: 'Bulk CSV/JSON finding and asset import' },
    { name: 'Import', description: 'Format-specific import (SARIF, CycloneDX, CSV, JSON)' },
    { name: 'Exports', description: 'Data export and scheduled export management' },
    { name: 'Reports', description: 'Executive, findings, compliance, and asset reports' },
    { name: 'Vulnerabilities', description: 'CVE/NVD vulnerability database with KEV and EPSS' },
    { name: 'Scanner', description: 'Scanner registration, task assignment, and results' },
    { name: 'Integrations', description: 'Email and webhook integration management' },
    { name: 'Notifications', description: 'Notification rules and event dispatching' },
    { name: 'Compliance', description: 'Compliance framework mapping and assessment' },
    { name: 'RedOPS', description: 'AI-powered penetration testing — campaigns, agents, and findings' },
  ],

  // ─── Paths ──────────────────────────────────────────────────────────
  paths: {
    // ── Health ─────────────────────────────────────────────────────────
    '/': {
      get: {
        tags: ['Health'],
        summary: 'API info',
        security: [],
        responses: {
          200: { description: 'API metadata', content: { 'application/json': { schema: { type: 'object', properties: { name: { type: 'string' }, version: { type: 'string' }, status: { type: 'string' }, environment: { type: 'string' } } } } } },
        },
      },
    },
    '/health': {
      get: {
        tags: ['Health'],
        summary: 'Health check',
        security: [],
        responses: { 200: { description: 'OK', content: { 'application/json': { schema: { type: 'object', properties: { status: { type: 'string' }, timestamp: { type: 'string' } } } } } } },
      },
    },

    // ── Auth ───────────────────────────────────────────────────────────
    '/api/v1/auth/register': {
      post: {
        tags: ['Auth'],
        summary: 'Register a new user',
        description: 'First user auto-becomes platform_admin (bootstrap). Subsequent users require platform_admin role.',
        security: [],
        requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/RegisterRequest' } } } },
        responses: {
          201: { description: 'User created', content: { 'application/json': { schema: { $ref: '#/components/schemas/User' } } } },
          400: { description: 'Validation error', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          409: { description: 'Email already registered' },
        },
      },
    },
    '/api/v1/auth/login': {
      post: {
        tags: ['Auth'],
        summary: 'Login and receive JWT',
        security: [],
        requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/LoginRequest' } } } },
        responses: {
          200: { description: 'JWT token', content: { 'application/json': { schema: { $ref: '#/components/schemas/LoginResponse' } } } },
          401: { description: 'Invalid credentials' },
        },
      },
    },
    '/api/v1/auth/logout': {
      post: { tags: ['Auth'], summary: 'Logout (invalidate session)', responses: { 200: { description: 'Logged out' } } },
    },
    '/api/v1/auth/me': {
      get: { tags: ['Auth'], summary: 'Get current user profile', responses: { 200: { description: 'User profile', content: { 'application/json': { schema: { $ref: '#/components/schemas/User' } } } } } },
    },
    '/api/v1/auth/password': {
      put: {
        tags: ['Auth'],
        summary: 'Change password',
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['current_password', 'new_password'], properties: { current_password: { type: 'string' }, new_password: { type: 'string', minLength: 8 } } } } } },
        responses: { 200: { description: 'Password changed' } },
      },
    },
    '/api/v1/auth/api-keys': {
      get: { tags: ['Auth'], summary: 'List own API keys', responses: { 200: { description: 'API keys list' } } },
      post: {
        tags: ['Auth'],
        summary: 'Create API key',
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['name'], properties: { name: { type: 'string' }, permissions: { type: 'string' }, expires_in_days: { type: 'integer' } } } } } },
        responses: { 201: { description: 'API key created (raw key returned once)' } },
      },
    },
    '/api/v1/auth/api-keys/{id}': {
      delete: { tags: ['Auth'], summary: 'Revoke an API key', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Deleted' } } },
    },
    '/api/v1/auth/users': {
      get: {
        tags: ['Auth'],
        summary: 'List users (admin)',
        parameters: [
          { $ref: '#/components/parameters/page' },
          { $ref: '#/components/parameters/pageSize' },
          { name: 'search', in: 'query', schema: { type: 'string' } },
        ],
        responses: { 200: { description: 'Paginated user list' } },
      },
      post: {
        tags: ['Auth'],
        summary: 'Create user (admin)',
        requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/RegisterRequest' } } } },
        responses: { 201: { description: 'User created' } },
      },
    },
    '/api/v1/auth/users/{id}': {
      put: { tags: ['Auth'], summary: 'Update user (admin)', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Updated' } } },
      delete: { tags: ['Auth'], summary: 'Delete user (admin)', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Deleted' } } },
    },
    '/api/v1/auth/sessions': {
      get: { tags: ['Auth'], summary: 'List active sessions', responses: { 200: { description: 'Sessions list' } } },
    },

    // ── Assets ─────────────────────────────────────────────────────────
    '/api/v1/assets': {
      get: {
        tags: ['Assets'],
        summary: 'List assets',
        parameters: [
          { name: 'search', in: 'query', schema: { type: 'string' } },
          { name: 'type', in: 'query', schema: { type: 'string' } },
          { name: 'sort_by', in: 'query', schema: { type: 'string', enum: ['hostname', 'risk_score', 'asset_type', 'last_seen', 'created_at'], default: 'last_seen' } },
          { $ref: '#/components/parameters/sortOrder' },
          { $ref: '#/components/parameters/page' },
          { $ref: '#/components/parameters/pageSize' },
        ],
        responses: { 200: { description: 'Paginated asset list' } },
      },
      post: {
        tags: ['Assets'],
        summary: 'Create asset',
        requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/CreateAssetRequest' } } } },
        responses: { 201: { description: 'Asset created' } },
      },
    },
    '/api/v1/assets/{id}': {
      get: { tags: ['Assets'], summary: 'Get asset with findings', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Asset detail' }, 404: { description: 'Not found' } } },
      put: { tags: ['Assets'], summary: 'Update asset', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Updated' } } },
      delete: { tags: ['Assets'], summary: 'Delete asset and related findings', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Deleted' } } },
    },
    '/api/v1/assets/{id}/summary': {
      get: { tags: ['Assets'], summary: 'Get asset severity summary', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Severity counts' } } },
    },

    // ── Findings ───────────────────────────────────────────────────────
    '/api/v1/findings': {
      get: {
        tags: ['Findings'],
        summary: 'List findings',
        parameters: [
          { name: 'severity', in: 'query', schema: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] } },
          { name: 'state', in: 'query', schema: { type: 'string', enum: ['open', 'acknowledged', 'resolved', 'false_positive', 'reopened', 'fixed', 'accepted'] } },
          { name: 'vendor', in: 'query', schema: { type: 'string' } },
          { name: 'asset_id', in: 'query', schema: { type: 'string' } },
          { name: 'search', in: 'query', schema: { type: 'string' } },
          { name: 'sort_by', in: 'query', schema: { type: 'string', enum: ['severity', 'title', 'frs_score', 'last_seen', 'created_at'], default: 'severity' } },
          { $ref: '#/components/parameters/sortOrder' },
          { $ref: '#/components/parameters/page' },
          { $ref: '#/components/parameters/pageSize' },
        ],
        responses: { 200: { description: 'Paginated findings list' } },
      },
      post: {
        tags: ['Findings'],
        summary: 'Create finding',
        requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/CreateFindingRequest' } } } },
        responses: { 201: { description: 'Finding created' } },
      },
    },
    '/api/v1/findings/{id}': {
      get: { tags: ['Findings'], summary: 'Get finding with asset and vulnerability data', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Finding detail' }, 404: { description: 'Not found' } } },
      put: {
        tags: ['Findings'],
        summary: 'Update finding',
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { state: { type: 'string' }, severity: { type: 'string' }, description: { type: 'string' }, solution: { type: 'string' } } } } } },
        responses: { 200: { description: 'Updated' } },
      },
    },
    '/api/v1/findings/{id}/state': {
      patch: {
        tags: ['Findings'],
        summary: 'Update finding state',
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['state'], properties: { state: { type: 'string', enum: ['open', 'fixed', 'accepted', 'false_positive', 'reopened'] } } } } } },
        responses: { 200: { description: 'State updated' } },
      },
    },
    '/api/v1/findings/bulk/state': {
      post: {
        tags: ['Findings'],
        summary: 'Bulk update finding states',
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['ids', 'state'], properties: { ids: { type: 'array', items: { type: 'string' } }, state: { type: 'string' } } } } } },
        responses: { 200: { description: 'Bulk updated' } },
      },
    },
    '/api/v1/findings/stats/severity': {
      get: { tags: ['Findings'], summary: 'Severity breakdown', parameters: [{ name: 'state', in: 'query', schema: { type: 'string', default: 'open' } }], responses: { 200: { description: 'Severity counts' } } },
    },
    '/api/v1/findings/stats/vendors': {
      get: { tags: ['Findings'], summary: 'Vendor breakdown (open findings)', responses: { 200: { description: 'Vendor counts' } } },
    },

    // ── Scans ──────────────────────────────────────────────────────────
    '/api/v1/scans': {
      get: {
        tags: ['Scans'],
        summary: 'List scans',
        parameters: [
          { name: 'status', in: 'query', schema: { type: 'string', enum: ['pending', 'running', 'completed', 'failed', 'cancelled'] } },
          { name: 'type', in: 'query', schema: { type: 'string' } },
          { name: 'sort_by', in: 'query', schema: { type: 'string', enum: ['name', 'status', 'scan_type', 'created_at', 'findings_count'], default: 'created_at' } },
          { $ref: '#/components/parameters/sortOrder' },
          { $ref: '#/components/parameters/page' },
          { $ref: '#/components/parameters/pageSize' },
        ],
        responses: { 200: { description: 'Paginated scans list' } },
      },
      post: {
        tags: ['Scans'],
        summary: 'Create scan',
        requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/CreateScanRequest' } } } },
        responses: { 201: { description: 'Scan created' } },
      },
    },
    '/api/v1/scans/active': { get: { tags: ['Scans'], summary: 'List active scans with task progress', responses: { 200: { description: 'Active scans with progress' } } } },
    '/api/v1/scans/stats/summary': { get: { tags: ['Scans'], summary: 'Scan statistics summary', responses: { 200: { description: 'Stats' } } } },
    '/api/v1/scans/{id}': {
      get: { tags: ['Scans'], summary: 'Get scan', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Scan detail' } } },
      delete: { tags: ['Scans'], summary: 'Delete scan', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Deleted' } } },
    },
    '/api/v1/scans/{id}/start': { post: { tags: ['Scans'], summary: 'Start a pending scan', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Scan started' }, 409: { description: 'Invalid state transition' } } } },
    '/api/v1/scans/{id}/cancel': { post: { tags: ['Scans'], summary: 'Cancel a running scan', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Scan cancelled' } } } },
    '/api/v1/scans/{id}/status': { patch: { tags: ['Scans'], summary: 'Update scan status', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Status updated' } } } },
    '/api/v1/scans/{id}/tasks': { get: { tags: ['Scans'], summary: 'List scan tasks', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Tasks with summary' } } } },

    // ── Dashboard ──────────────────────────────────────────────────────
    '/api/v1/dashboard/overview': { get: { tags: ['Dashboard'], summary: 'Dashboard overview (cached 5min)', responses: { 200: { description: 'Overview', content: { 'application/json': { schema: { $ref: '#/components/schemas/DashboardOverview' } } } } } } },
    '/api/v1/dashboard/stats': { get: { tags: ['Dashboard'], summary: 'Dashboard statistics', responses: { 200: { description: 'Stats' } } } },
    '/api/v1/dashboard/trends/findings': { get: { tags: ['Dashboard'], summary: 'Finding trends over time', parameters: [{ name: 'days', in: 'query', schema: { type: 'integer', default: 30 } }], responses: { 200: { description: 'Daily trend data' } } } },
    '/api/v1/dashboard/trends/remediation': { get: { tags: ['Dashboard'], summary: 'Remediation trends', parameters: [{ name: 'days', in: 'query', schema: { type: 'integer', default: 30 } }], responses: { 200: { description: 'Daily remediation counts' } } } },
    '/api/v1/dashboard/metrics/mttr': { get: { tags: ['Dashboard'], summary: 'Mean time to remediate by severity', responses: { 200: { description: 'MTTR data' } } } },
    '/api/v1/dashboard/metrics/risk-score': { get: { tags: ['Dashboard'], summary: 'Overall risk score (0-100) and grade (A-F)', responses: { 200: { description: 'Risk score' } } } },
    '/api/v1/dashboard/breakdown/vendors': { get: { tags: ['Dashboard'], summary: 'Findings breakdown by vendor', responses: { 200: { description: 'Vendor breakdown' } } } },
    '/api/v1/dashboard/breakdown/asset-types': { get: { tags: ['Dashboard'], summary: 'Findings breakdown by asset type', responses: { 200: { description: 'Asset type breakdown' } } } },

    // ── Ingest ──────────────────────────────────────────────────────────
    '/api/v1/ingest/jobs': { get: { tags: ['Ingest'], summary: 'List ingestion jobs', parameters: [{ name: 'limit', in: 'query', schema: { type: 'integer', default: 20 } }, { name: 'vendor', in: 'query', schema: { type: 'string' } }, { name: 'status', in: 'query', schema: { type: 'string' } }], responses: { 200: { description: 'Job list' } } } },
    '/api/v1/ingest/jobs/{id}': { get: { tags: ['Ingest'], summary: 'Get ingestion job', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Job detail' }, 404: { description: 'Not found' } } } },
    '/api/v1/ingest/upload': {
      post: {
        tags: ['Ingest'],
        summary: 'Upload findings or assets (JSON, CSV, or file)',
        description: 'Supports application/json, text/csv, and multipart/form-data. Use ?vendor= to apply vendor-specific CSV column mappings (tenable, qualys, rapid7, generic). Use ?type=assets for asset CSV import.',
        parameters: [
          { name: 'vendor', in: 'query', schema: { type: 'string', enum: ['generic', 'tenable', 'nessus', 'qualys', 'rapid7', 'nexpose'], default: 'generic' } },
          { name: 'type', in: 'query', schema: { type: 'string', enum: ['findings', 'assets', 'auto'], default: 'findings' } },
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': { schema: { type: 'array', items: { type: 'object' }, description: 'Array of findings, or { findings: [...] } or { vulnerabilities: [...] }' } },
            'text/csv': { schema: { type: 'string', description: 'Raw CSV with header row' } },
            'multipart/form-data': { schema: { type: 'object', properties: { file: { type: 'string', format: 'binary' }, format: { type: 'string', enum: ['csv', 'json'] } }, required: ['file'] } },
          },
        },
        responses: {
          200: { description: 'Import result', content: { 'application/json': { schema: { $ref: '#/components/schemas/UploadResponse' } } } },
          400: { description: 'Validation error', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
        },
      },
    },
    '/api/v1/ingest/vendors': { get: { tags: ['Ingest'], summary: 'List supported CSV vendor presets', responses: { 200: { description: 'Vendor list' } } } },

    // ── Import ──────────────────────────────────────────────────────────
    '/api/v1/import': {
      post: {
        tags: ['Import'],
        summary: 'Import findings (CSV, JSON, SARIF, CycloneDX)',
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['format', 'data'], properties: { format: { type: 'string', enum: ['csv', 'json', 'sarif', 'cyclonedx'] }, data: { description: 'Raw data string or parsed object' } } } } } },
        responses: { 200: { description: 'Import result' } },
      },
    },
    '/api/v1/import/upload': { post: { tags: ['Import'], summary: 'Import findings via file upload', requestBody: { required: true, content: { 'multipart/form-data': { schema: { type: 'object', properties: { file: { type: 'string', format: 'binary' }, format: { type: 'string' } } } } } }, responses: { 200: { description: 'Import result' } } } },
    '/api/v1/import/assets': { post: { tags: ['Import'], summary: 'Import assets (CSV or JSON)', responses: { 200: { description: 'Import result' } } } },
    '/api/v1/import/assets/upload': { post: { tags: ['Import'], summary: 'Import assets via file upload', responses: { 200: { description: 'Import result' } } } },

    // ── Exports ─────────────────────────────────────────────────────────
    '/api/v1/exports/findings/csv': { get: { tags: ['Exports'], summary: 'Export findings as CSV', parameters: [{ name: 'severity', in: 'query', schema: { type: 'string' } }, { name: 'vendor', in: 'query', schema: { type: 'string' } }, { name: 'state', in: 'query', schema: { type: 'string', default: 'open' } }, { name: 'limit', in: 'query', schema: { type: 'integer', default: 10000 } }], responses: { 200: { description: 'CSV file download' } } } },
    '/api/v1/exports/findings/json': { get: { tags: ['Exports'], summary: 'Export findings as JSON', responses: { 200: { description: 'JSON file download' } } } },
    '/api/v1/exports/assets/csv': { get: { tags: ['Exports'], summary: 'Export assets as CSV', responses: { 200: { description: 'CSV file download' } } } },
    '/api/v1/exports/assets/json': { get: { tags: ['Exports'], summary: 'Export assets as JSON', responses: { 200: { description: 'JSON file download' } } } },
    '/api/v1/exports/schedule': { post: { tags: ['Exports'], summary: 'Create export schedule', responses: { 201: { description: 'Schedule created' } } } },
    '/api/v1/exports/schedules': { get: { tags: ['Exports'], summary: 'List export schedules', responses: { 200: { description: 'Schedules list' } } } },
    '/api/v1/exports/schedules/{id}': {
      patch: { tags: ['Exports'], summary: 'Update export schedule', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Updated' } } },
      delete: { tags: ['Exports'], summary: 'Delete export schedule', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Deleted' } } },
    },
    '/api/v1/exports/run/{id}': { post: { tags: ['Exports'], summary: 'Trigger scheduled export now', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Export triggered' } } } },

    // ── Reports ─────────────────────────────────────────────────────────
    '/api/v1/reports/executive': { get: { tags: ['Reports'], summary: 'Executive summary report', parameters: [{ name: 'days', in: 'query', schema: { type: 'integer', default: 30 } }], responses: { 200: { description: 'Executive summary', content: { 'application/json': { schema: { $ref: '#/components/schemas/ExecutiveSummary' } } } } } } },
    '/api/v1/reports/findings': { get: { tags: ['Reports'], summary: 'Findings report', responses: { 200: { description: 'Findings report data' } } } },
    '/api/v1/reports/compliance': { get: { tags: ['Reports'], summary: 'Compliance report', responses: { 200: { description: 'Compliance data' } } } },
    '/api/v1/reports/assets': { get: { tags: ['Reports'], summary: 'Assets report', responses: { 200: { description: 'Assets data' } } } },
    '/api/v1/reports/generate': { post: { tags: ['Reports'], summary: 'Generate and store report (PDF/CSV/JSON)', responses: { 201: { description: 'Report generated' } } } },
    '/api/v1/reports/{id}/download': { get: { tags: ['Reports'], summary: 'Download generated report', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Binary file' } } } },
    '/api/v1/reports/list/all': { get: { tags: ['Reports'], summary: 'List all generated reports', responses: { 200: { description: 'Reports list' } } } },
    '/api/v1/reports/{id}': { delete: { tags: ['Reports'], summary: 'Delete report (admin)', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Deleted' } } } },

    // ── Vulnerabilities ─────────────────────────────────────────────────
    '/api/v1/vulnerabilities': {
      get: { tags: ['Vulnerabilities'], summary: 'List vulnerabilities', parameters: [{ $ref: '#/components/parameters/limit' }, { $ref: '#/components/parameters/offset' }, { name: 'min_cvss', in: 'query', schema: { type: 'number' } }, { name: 'in_kev', in: 'query', schema: { type: 'boolean' } }, { name: 'sort_by', in: 'query', schema: { type: 'string', enum: ['cvss_score', 'epss_score', 'published_at', 'cve_id', 'created_at'], default: 'cvss_score' } }], responses: { 200: { description: 'Vulnerability list' } } },
      post: { tags: ['Vulnerabilities'], summary: 'Create or upsert vulnerability', responses: { 201: { description: 'Created/updated' } } },
    },
    '/api/v1/vulnerabilities/stats': { get: { tags: ['Vulnerabilities'], summary: 'Vulnerability database statistics', responses: { 200: { description: 'Stats' } } } },
    '/api/v1/vulnerabilities/search': { get: { tags: ['Vulnerabilities'], summary: 'Search vulnerabilities by CVE, CWE, product, vendor', parameters: [{ name: 'q', in: 'query', schema: { type: 'string' } }, { name: 'cve_pattern', in: 'query', schema: { type: 'string' } }, { name: 'cwe', in: 'query', schema: { type: 'string' } }], responses: { 200: { description: 'Search results' } } } },
    '/api/v1/vulnerabilities/kev': { get: { tags: ['Vulnerabilities'], summary: 'CISA KEV catalogue entries', responses: { 200: { description: 'KEV list' } } } },
    '/api/v1/vulnerabilities/high-risk': { get: { tags: ['Vulnerabilities'], summary: 'High-risk vulnerabilities (high CVSS + EPSS)', responses: { 200: { description: 'High risk list' } } } },
    '/api/v1/vulnerabilities/{cve}': {
      get: { tags: ['Vulnerabilities'], summary: 'Get vulnerability by CVE ID', parameters: [{ name: 'cve', in: 'path', required: true, schema: { type: 'string', pattern: '^CVE-\\d{4}-\\d{4,}$' } }], responses: { 200: { description: 'Vulnerability detail' } } },
      delete: { tags: ['Vulnerabilities'], summary: 'Delete vulnerability', parameters: [{ name: 'cve', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Deleted' } } },
    },
    '/api/v1/vulnerabilities/bulk': { post: { tags: ['Vulnerabilities'], summary: 'Bulk upsert vulnerabilities (max 1000)', responses: { 200: { description: 'Bulk result' } } } },
    '/api/v1/vulnerabilities/sync': { post: { tags: ['Vulnerabilities'], summary: 'Trigger NVD sync (admin)', responses: { 202: { description: 'Sync started' }, 409: { description: 'Already running' } } } },
    '/api/v1/vulnerabilities/sync/status': { get: { tags: ['Vulnerabilities'], summary: 'NVD sync status', responses: { 200: { description: 'Sync status' } } } },
    '/api/v1/vulnerabilities/sync/kev': { post: { tags: ['Vulnerabilities'], summary: 'Sync CISA KEV data', responses: { 200: { description: 'KEV sync result' } } } },
    '/api/v1/vulnerabilities/sync/epss': { post: { tags: ['Vulnerabilities'], summary: 'Sync EPSS scores', responses: { 200: { description: 'EPSS sync result' } } } },

    // ── Scanner ─────────────────────────────────────────────────────────
    '/api/v1/scanner/register': { post: { tags: ['Scanner'], summary: 'Register scanner (admin)', responses: { 201: { description: 'Scanner registered with API key' } } } },
    '/api/v1/scanner': { get: { tags: ['Scanner'], summary: 'List scanners (admin)', responses: { 200: { description: 'Scanner list' } } } },
    '/api/v1/scanner/{id}': { delete: { tags: ['Scanner'], summary: 'Disable scanner (admin)', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Disabled' } } } },
    '/api/v1/scanner/tasks': { get: { tags: ['Scanner'], summary: 'List tasks (admin)', responses: { 200: { description: 'Task list' } } } },
    '/api/v1/scanner/tasks/next': { get: { tags: ['Scanner'], summary: 'Get next task (scanner-facing)', security: [{ scannerKeyAuth: [] }], responses: { 200: { description: 'Task assigned' }, 204: { description: 'No tasks' } } } },
    '/api/v1/scanner/tasks/{id}/start': { post: { tags: ['Scanner'], summary: 'Start assigned task (scanner-facing)', security: [{ scannerKeyAuth: [] }], parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Started' } } } },
    '/api/v1/scanner/tasks/{id}/results': { post: { tags: ['Scanner'], summary: 'Submit task results (scanner-facing)', security: [{ scannerKeyAuth: [] }], parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Results recorded' } } } },
    '/api/v1/scanner/heartbeat': { post: { tags: ['Scanner'], summary: 'Scanner heartbeat', security: [{ scannerKeyAuth: [] }], responses: { 200: { description: 'OK' } } } },

    // ── Integrations ────────────────────────────────────────────────────
    '/api/v1/integrations': {
      get: { tags: ['Integrations'], summary: 'List integrations', responses: { 200: { description: 'Integration list' } } },
      post: { tags: ['Integrations'], summary: 'Create integration (email/webhook)', responses: { 201: { description: 'Created' } } },
    },
    '/api/v1/integrations/{id}': {
      get: { tags: ['Integrations'], summary: 'Get integration', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Integration detail' } } },
      put: { tags: ['Integrations'], summary: 'Update integration', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Updated' } } },
      delete: { tags: ['Integrations'], summary: 'Delete integration', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Deleted' } } },
    },
    '/api/v1/integrations/{id}/test': { post: { tags: ['Integrations'], summary: 'Test integration connectivity', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Test result' } } } },
    '/api/v1/integrations/{id}/dispatch': { post: { tags: ['Integrations'], summary: 'Dispatch event through integration', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Dispatch result' } } } },
    '/api/v1/integrations/{id}/logs': { get: { tags: ['Integrations'], summary: 'Integration dispatch logs', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Log list' } } } },
    '/api/v1/integrations/logs/recent': { get: { tags: ['Integrations'], summary: 'Recent integration logs', responses: { 200: { description: 'Recent logs' } } } },

    // ── Notifications ───────────────────────────────────────────────────
    '/api/v1/notifications': {
      get: { tags: ['Notifications'], summary: 'List notification rules', responses: { 200: { description: 'Rules list' } } },
      post: { tags: ['Notifications'], summary: 'Create notification rule', responses: { 201: { description: 'Rule created' } } },
    },
    '/api/v1/notifications/stats': { get: { tags: ['Notifications'], summary: 'Notification statistics', responses: { 200: { description: 'Stats' } } } },
    '/api/v1/notifications/{id}': {
      put: { tags: ['Notifications'], summary: 'Update notification rule', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Updated' } } },
      delete: { tags: ['Notifications'], summary: 'Delete notification rule', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Deleted' } } },
    },
    '/api/v1/notifications/{id}/test': { post: { tags: ['Notifications'], summary: 'Test notification rule', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Test result' } } } },
    '/api/v1/notifications/log': { get: { tags: ['Notifications'], summary: 'Notification delivery log', responses: { 200: { description: 'Log entries' } } } },

    // ── Compliance ──────────────────────────────────────────────────────
    '/api/v1/compliance': { get: { tags: ['Compliance'], summary: 'List compliance frameworks', responses: { 200: { description: 'Framework list' } } } },
    '/api/v1/compliance/mappings': { get: { tags: ['Compliance'], summary: 'List compliance mappings', responses: { 200: { description: 'Mappings list' } } } },
    '/api/v1/compliance/{id}': { get: { tags: ['Compliance'], summary: 'Get framework with controls and stats', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Framework detail' } } } },
    '/api/v1/compliance/{id}/controls': { get: { tags: ['Compliance'], summary: 'List framework controls', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Controls list' } } } },
    '/api/v1/compliance/{id}/gaps': { get: { tags: ['Compliance'], summary: 'Identify compliance gaps', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Gaps list' } } } },
    '/api/v1/compliance/seed': { post: { tags: ['Compliance'], summary: 'Seed compliance frameworks (admin)', responses: { 200: { description: 'Seeded' } } } },
    '/api/v1/compliance/assess': { post: { tags: ['Compliance'], summary: 'Assess control compliance', responses: { 201: { description: 'Assessment recorded' } } } },

    // ── ForgeRedOPS ────────────────────────────────────────────────────
    '/api/v1/redops/overview': { get: { tags: ['RedOPS'], summary: 'RedOPS dashboard overview stats', responses: { 200: { description: 'Campaign, finding, and agent statistics' } } } },

    '/api/v1/redops/campaigns': {
      get: { tags: ['RedOPS'], summary: 'List pen test campaigns', parameters: [{ name: 'status', in: 'query', schema: { type: 'string' } }, { name: 'type', in: 'query', schema: { type: 'string' } }], responses: { 200: { description: 'Paginated campaign list' } } },
      post: { tags: ['RedOPS'], summary: 'Create a new pen test campaign', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['name', 'target_scope'], properties: { name: { type: 'string' }, description: { type: 'string' }, campaign_type: { type: 'string', enum: ['full', 'targeted', 'continuous', 'validation'] }, target_scope: { type: 'object' }, exploitation_level: { type: 'string', enum: ['passive', 'safe', 'moderate', 'aggressive'] }, agent_categories: { type: 'array', items: { type: 'string' } } } } } } }, responses: { 201: { description: 'Campaign created' } } },
    },
    '/api/v1/redops/campaigns/{id}': {
      get: { tags: ['RedOPS'], summary: 'Get campaign by ID', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Campaign detail' } } },
      put: { tags: ['RedOPS'], summary: 'Update campaign', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Updated campaign' } } },
      delete: { tags: ['RedOPS'], summary: 'Delete campaign', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Campaign deleted' } } },
    },
    '/api/v1/redops/campaigns/{id}/launch': { post: { tags: ['RedOPS'], summary: 'Launch campaign — creates agents and starts pen test', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Campaign launched with agents' } } } },
    '/api/v1/redops/campaigns/{id}/cancel': { post: { tags: ['RedOPS'], summary: 'Cancel running campaign', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Campaign cancelled' } } } },
    '/api/v1/redops/campaigns/{id}/agents': { get: { tags: ['RedOPS'], summary: 'List agents for a campaign', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }, { name: 'status', in: 'query', schema: { type: 'string' } }, { name: 'category', in: 'query', schema: { type: 'string' } }], responses: { 200: { description: 'Agent list' } } } },
    '/api/v1/redops/campaigns/{id}/findings': { get: { tags: ['RedOPS'], summary: 'List findings for a campaign', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }, { name: 'severity', in: 'query', schema: { type: 'string' } }, { name: 'exploitable', in: 'query', schema: { type: 'string' } }], responses: { 200: { description: 'Paginated findings' } } } },

    '/api/v1/redops/agents/{id}': { get: { tags: ['RedOPS'], summary: 'Get agent details', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Agent detail' } } } },
    '/api/v1/redops/agent-types': { get: { tags: ['RedOPS'], summary: 'List all 24 agent type definitions', parameters: [{ name: 'category', in: 'query', schema: { type: 'string', enum: ['web', 'api', 'cloud', 'network', 'identity'] } }], responses: { 200: { description: 'Agent type definitions with MITRE/OWASP coverage' } } } },

    '/api/v1/redops/findings': { get: { tags: ['RedOPS'], summary: 'List all pen test findings (global)', parameters: [{ name: 'severity', in: 'query', schema: { type: 'string' } }, { name: 'exploitable', in: 'query', schema: { type: 'string' } }, { name: 'status', in: 'query', schema: { type: 'string' } }], responses: { 200: { description: 'Paginated findings across all campaigns' } } } },
    '/api/v1/redops/findings/{id}': { put: { tags: ['RedOPS'], summary: 'Update finding status', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { status: { type: 'string', enum: ['open', 'confirmed', 'remediated', 'accepted_risk', 'false_positive'] }, remediation: { type: 'string' } } } } } }, responses: { 200: { description: 'Updated finding' } } } },
  },
} as const;
