import { readFileSync } from 'node:fs';
import { defineConfig } from 'vitest/config';

const pkg = JSON.parse(readFileSync('./package.json', 'utf-8')) as { version: string };

export default defineConfig({
  define: {
    __ATTSD_SDK_VERSION__: JSON.stringify(pkg.version),
  },
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
  },
});
