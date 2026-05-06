/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        head: ['Syne', 'sans-serif'],
        mono: ['IBM Plex Mono', 'monospace'],
      },
      colors: {
        bg:      '#090b10',
        surface: '#0e1118',
        surface2:'#151922',
        accent:  '#00e5a0',
        accent2: '#0066ff',
        danger:  '#ff4d6d',
        warn:    '#f59e0b',
        info:    '#38bdf8',
        muted:   '#6b7280',
      },
    },
  },
  plugins: [],
}
