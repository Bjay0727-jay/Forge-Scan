/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ['class'],
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    container: {
      center: true,
      padding: '1.5rem',
      screens: {
        '2xl': '1400px',
      },
    },
    extend: {
      colors: {
        border: 'hsl(var(--border))',
        input: 'hsl(var(--input))',
        ring: 'hsl(var(--ring))',
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        primary: {
          DEFAULT: 'hsl(var(--primary))',
          foreground: 'hsl(var(--primary-foreground))',
        },
        secondary: {
          DEFAULT: 'hsl(var(--secondary))',
          foreground: 'hsl(var(--secondary-foreground))',
        },
        destructive: {
          DEFAULT: 'hsl(var(--destructive))',
          foreground: 'hsl(var(--destructive-foreground))',
        },
        muted: {
          DEFAULT: 'hsl(var(--muted))',
          foreground: 'hsl(var(--muted-foreground))',
        },
        accent: {
          DEFAULT: 'hsl(var(--accent))',
          foreground: 'hsl(var(--accent-foreground))',
        },
        popover: {
          DEFAULT: 'hsl(var(--popover))',
          foreground: 'hsl(var(--popover-foreground))',
        },
        card: {
          DEFAULT: 'hsl(var(--card))',
          foreground: 'hsl(var(--card-foreground))',
        },
        // ===== Forge Cyber Defense Brand =====
        navy: {
          50: '#e6edf5',
          100: '#c0d0e3',
          200: '#96b0ce',
          300: '#6b8fb9',
          400: '#4b77a9',
          500: '#2b5f9a',
          600: '#1a3a5c',
          700: '#0F2A4A',
          800: '#091e36',
          900: '#060f1a',
        },
        teal: {
          400: '#14b8a6',
          500: '#0D9488',
          600: '#0f766e',
          700: '#0d6560',
        },
        severity: {
          critical: '#dc2626',
          high: '#ea580c',
          medium: '#ca8a04',
          low: '#16a34a',
          info: '#2563eb',
        },
        // Risk-grade — Executive Scorecard glyph only
        grade: {
          a: '#22c55e',
          b: '#3b82f6',
          c: '#eab308',
          d: '#f97316',
          f: '#ef4444',
        },
      },
      fontFamily: {
        heading: ['Sora', 'Inter', 'system-ui', 'sans-serif'],
        body: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SF Mono', 'Menlo', 'monospace'],
      },
      fontSize: {
        // Forge type scale — compounds against 14px html base
        'forge-xs':   ['0.75rem',   { lineHeight: '1.4' }],
        'forge-sm':   ['0.8125rem', { lineHeight: '1.45' }],
        'forge-base': ['0.875rem',  { lineHeight: '1.5' }],
        'forge-md':   ['1rem',      { lineHeight: '1.5' }],
        'forge-lg':   ['1.125rem',  { lineHeight: '1.45' }],
        'forge-xl':   ['1.5rem',    { lineHeight: '1.25' }],
        'forge-2xl':  ['2rem',      { lineHeight: '1.2' }],
        'forge-3xl':  ['2.75rem',   { lineHeight: '1.1' }],
        'forge-hero': ['4rem',      { lineHeight: '1.05' }],
      },
      letterSpacing: {
        eyebrow: '0.35em',
        kicker:  '0.18em',
      },
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
      },
      boxShadow: {
        'forge-card': '0 1px 2px 0 rgba(0,0,0,0.25)',
        'forge-pop':  '0 10px 30px -10px rgba(0,0,0,0.5)',
        'forge-glow': '0 0 20px rgba(13,148,136,0.15)',
        'forge-ring': '0 0 0 1px hsl(174 84% 32% / 0.1)',
      },
      transitionTimingFunction: {
        'forge-out':    'cubic-bezier(0.16, 1, 0.3, 1)',
        'forge-inout':  'cubic-bezier(0.65, 0, 0.35, 1)',
        'forge-in':     'cubic-bezier(0.7, 0, 0.84, 0)',
        'forge-spring': 'cubic-bezier(0.34, 1.56, 0.64, 1)',
        'forge-alert':  'cubic-bezier(0.4, 0, 0.2, 1)',
      },
      transitionDuration: {
        'forge-instant': '80ms',
        'forge-fast':    '120ms',
        'forge-base':    '200ms',
        'forge-slow':    '360ms',
      },
      keyframes: {
        'accordion-down': {
          from: { height: 0 },
          to: { height: 'var(--radix-accordion-content-height)' },
        },
        'accordion-up': {
          from: { height: 'var(--radix-accordion-content-height)' },
          to: { height: 0 },
        },
        'forge-pulse': {
          '0%, 100%': { opacity: '0.55', transform: 'scale(1)' },
          '50%':      { opacity: '1',    transform: 'scale(1.06)' },
        },
        'forge-flash-critical': {
          '0%':   { backgroundColor: 'rgba(220, 38, 38, 0)' },
          '20%':  { backgroundColor: 'rgba(220, 38, 38, 0.25)' },
          '100%': { backgroundColor: 'rgba(220, 38, 38, 0)' },
        },
        'forge-shimmer': {
          '0%':   { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
        'forge-toast-in': {
          from: { opacity: '0', transform: 'translateY(12px) scale(0.96)' },
          to:   { opacity: '1', transform: 'translateY(0) scale(1)' },
        },
        'forge-drawer-in': {
          from: { transform: 'translateX(100%)' },
          to:   { transform: 'translateX(0)' },
        },
        'forge-modal-in': {
          from: { opacity: '0', transform: 'translateY(8px) scale(0.98)' },
          to:   { opacity: '1', transform: 'translateY(0) scale(1)' },
        },
        'forge-scan-beam': {
          '0%':   { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' },
        },
      },
      animation: {
        'accordion-down': 'accordion-down 0.2s ease-out',
        'accordion-up':   'accordion-up 0.2s ease-out',
        'forge-pulse':    'forge-pulse 1400ms cubic-bezier(0.65, 0, 0.35, 1) infinite',
        'forge-flash':    'forge-flash-critical 600ms cubic-bezier(0.4, 0, 0.2, 1) 1',
        'forge-shimmer':  'forge-shimmer 1.6s linear infinite',
        'forge-toast-in': 'forge-toast-in 200ms cubic-bezier(0.16, 1, 0.3, 1)',
        'forge-drawer-in':'forge-drawer-in 360ms cubic-bezier(0.16, 1, 0.3, 1)',
        'forge-modal-in': 'forge-modal-in 200ms cubic-bezier(0.16, 1, 0.3, 1)',
        'forge-scan-beam':'forge-scan-beam 1.8s linear infinite',
      },
    },
  },
  plugins: [require('tailwindcss-animate')],
};
