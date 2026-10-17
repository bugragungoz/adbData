import { defineConfig } from 'vitest/config';

export default defineConfig({
  esbuild: { jsx: 'automatic', jsxImportSource: 'preact' },
  define: { __APP_VERSION__: JSON.stringify('test') },
  test: {
    environment: 'jsdom',
    // Lets Testing Library unmount what each test rendered.
    globals: true,
    include: ['src/**/*.test.{ts,tsx}'],
  },
});
