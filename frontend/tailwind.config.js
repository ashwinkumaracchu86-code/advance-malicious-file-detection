/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          50: '#f0fdf4',
          100: '#dcfce7',
          200: '#bbf7d0',
          300: '#86efac',
          400: '#4ade80',
          500: '#22c55e',
          600: '#16a34a',
          700: '#15803d',
          800: '#166534',
          900: '#14532d',
          950: '#052e16',
        },
        dark: {
          50: 'rgb(var(--dark-50) / <alpha-value>)',
          100: 'rgb(var(--dark-100) / <alpha-value>)',
          200: 'rgb(var(--dark-200) / <alpha-value>)',
          300: 'rgb(var(--dark-300) / <alpha-value>)',
          400: 'rgb(var(--dark-400) / <alpha-value>)',
          500: 'rgb(var(--dark-500) / <alpha-value>)',
          600: 'rgb(var(--dark-600) / <alpha-value>)',
          700: 'rgb(var(--dark-700) / <alpha-value>)',
          800: 'rgb(var(--dark-800) / <alpha-value>)',
          900: 'rgb(var(--dark-900) / <alpha-value>)',
          950: 'rgb(var(--dark-950) / <alpha-value>)',
        },
        surface: 'rgb(var(--surface) / <alpha-value>)',
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      }
    },
  },
  plugins: [],
}
