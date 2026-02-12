# Deploying ForgeScan Dashboard to Cloudflare Pages

## Option 1: GitHub Integration (Recommended)

Cloudflare Pages can automatically build and deploy from your GitHub repository.

### Step 1: Go to Cloudflare Pages
1. Log in to [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Click **Workers & Pages** in the left sidebar
3. Click **Create** button
4. Select **Pages** tab
5. Click **Connect to Git**

### Step 2: Connect GitHub Repository
1. Select **GitHub** as your Git provider
2. Authorize Cloudflare to access your GitHub account
3. Select the repository: `Bjay0727-jay/Forge-Scan`
4. Click **Begin setup**

### Step 3: Configure Build Settings
Use these exact settings:

| Setting | Value |
|---------|-------|
| **Project name** | `forgescan-dashboard` |
| **Production branch** | `main` |
| **Framework preset** | `Vite` |
| **Build command** | `cd cloudflare/forgescan-dashboard && npm install && npm run build` |
| **Build output directory** | `cloudflare/forgescan-dashboard/dist` |
| **Root directory** | `/` (leave as root) |

### Step 4: Environment Variables
Add these environment variables:

| Variable | Value |
|----------|-------|
| `NODE_VERSION` | `18` |
| `VITE_API_URL` | `https://forgescan-api.<your-account>.workers.dev/api/v1` |

> **Note**: Replace `<your-account>` with your Cloudflare Workers subdomain, or use your custom domain if configured.

### Step 5: Deploy
Click **Save and Deploy**. Cloudflare will:
1. Clone your repository
2. Run the build command
3. Deploy the `dist/` folder to the edge

Your dashboard will be available at: `https://forgescan-dashboard.pages.dev`

---

## Option 2: Direct Upload (Manual)

If you prefer to build locally and upload:

### Step 1: Build Locally
```bash
cd cloudflare/forgescan-dashboard
npm install
npm run build
```

### Step 2: Upload via Cloudflare Dashboard
1. Go to **Workers & Pages** → **Create** → **Pages** → **Upload assets**
2. Name your project: `forgescan-dashboard`
3. Drag and drop the entire `dist/` folder contents
4. Click **Deploy site**

---

## Option 3: Wrangler CLI

If you have `wrangler` CLI configured with an API token:

```bash
cd cloudflare/forgescan-dashboard
npm install
npm run build
npm run deploy
```

---

## After Deployment

### Configure Custom Domain (Optional)
1. Go to your Pages project → **Custom domains**
2. Add your domain (e.g., `dashboard.forgescan.io`)
3. Follow DNS configuration instructions

### Update API URL
If your API is deployed at a different URL, update `VITE_API_URL`:
1. Go to Pages project → **Settings** → **Environment variables**
2. Update `VITE_API_URL` with your API Worker URL
3. Trigger a new deployment

---

## Troubleshooting

### Build Fails
- Ensure Node.js version is set to 18+ via `NODE_VERSION` environment variable
- Check that all dependencies are listed in `package.json`

### API Connection Issues
- Verify `VITE_API_URL` points to your deployed Worker
- Check CORS settings in the API Worker
- Ensure the API Worker is deployed and running

### Blank Page After Deploy
- Check browser console for errors
- Verify the build output contains `index.html`
- Ensure `dist/` folder structure is correct
