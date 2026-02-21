import { Hono } from 'hono';
import type { Env } from '../index';
import { openApiSpec } from '../openapi';

export const docs = new Hono<{ Bindings: Env }>();

// Serve the OpenAPI JSON spec
docs.get('/openapi.json', (c) => {
  return c.json(openApiSpec);
});

// Serve Swagger UI HTML page
docs.get('/', (c) => {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ForgeScan 360 API Documentation</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css" />
  <style>
    body { margin: 0; background: #fafafa; }
    .swagger-ui .topbar { display: none; }
    .swagger-ui .info { margin: 30px 0 10px; }
    .swagger-ui .info .title { font-size: 2rem; }
    .custom-header {
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
      color: white;
      padding: 20px 40px;
      display: flex;
      align-items: center;
      gap: 16px;
    }
    .custom-header h1 { margin: 0; font-size: 1.5rem; font-weight: 600; }
    .custom-header p { margin: 4px 0 0; opacity: 0.8; font-size: 0.9rem; }
    .badge {
      display: inline-block;
      background: #e94560;
      color: white;
      padding: 2px 10px;
      border-radius: 12px;
      font-size: 0.75rem;
      font-weight: 600;
      margin-left: 8px;
    }
  </style>
</head>
<body>
  <div class="custom-header">
    <div>
      <h1>ForgeScan 360 <span class="badge">API</span></h1>
      <p>Vulnerability Management Platform &mdash; 121 endpoints across 15 modules</p>
    </div>
  </div>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    SwaggerUIBundle({
      url: '/api/docs/openapi.json',
      dom_id: '#swagger-ui',
      deepLinking: true,
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
      layout: 'BaseLayout',
      defaultModelsExpandDepth: 1,
      defaultModelExpandDepth: 2,
      docExpansion: 'list',
      filter: true,
      showExtensions: true,
      tryItOutEnabled: true,
    });
  </script>
</body>
</html>`;

  return c.html(html);
});
