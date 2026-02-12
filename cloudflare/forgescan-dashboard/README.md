# ForgeScan Dashboard

A React-based dashboard for ForgeScan security vulnerability scanner, built with Vite, TypeScript, and Tailwind CSS.

## Features

- **Dashboard Overview**: Severity charts, risk scores, and trend analysis
- **Assets Management**: List, search, filter, and manage infrastructure assets
- **Findings View**: Browse and manage security findings with severity and state filters
- **Scan Management**: Create, start, cancel, and monitor security scans
- **Data Import**: Import security data from SARIF, CycloneDX, CSV, or JSON formats

## Tech Stack

- React 18
- TypeScript
- Vite
- Tailwind CSS
- Radix UI (shadcn/ui components)
- Recharts
- React Router

## Getting Started

### Prerequisites

- Node.js 18+
- npm or pnpm

### Installation

```bash
npm install
```

### Development

```bash
npm run dev
```

The dashboard will be available at http://localhost:3000

### Configuration

Create a `.env` file based on `.env.example`:

```bash
cp .env.example .env
```

Configure the API URL:

```
VITE_API_URL=http://localhost:8787/api
```

### Build

```bash
npm run build
```

### Deploy to Cloudflare Pages

```bash
npm run deploy
```

## Project Structure

```
src/
├── components/
│   ├── charts/       # Chart components (Recharts)
│   ├── layout/       # Layout components (Sidebar, Layout)
│   └── ui/           # UI components (Button, Card, etc.)
├── hooks/            # Custom React hooks
├── lib/              # Utilities and API client
├── pages/            # Page components
└── types/            # TypeScript type definitions
```

## API Integration

The dashboard communicates with the ForgeScan API. Configure the API base URL via the `VITE_API_URL` environment variable.

### Endpoints Used

- `GET /api/dashboard/stats` - Dashboard statistics
- `GET/POST /api/assets` - Asset management
- `GET/PUT /api/findings` - Findings management
- `GET/POST /api/scans` - Scan management
- `POST /api/import` - Data import

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VITE_API_URL` | ForgeScan API base URL | `/api` |

## License

MIT
