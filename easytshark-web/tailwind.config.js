/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}"
  ],
  theme: {
    extend: {
      colors: {
        "color-fill-3": "var(--color-fill-3)"
      },
    },
  },
  plugins: [],
  corePlugins: {
    preflight: false,
  },
}

