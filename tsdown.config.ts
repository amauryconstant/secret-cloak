import { defineConfig } from 'tsdown'

export default defineConfig({
    entry: ['src/index.ts'],
    format: ['esm'],
    outDir: 'dist',
    clean: true,
    target: 'node24',
    platform: 'node',
    dts: true,
    sourcemap: true,
    deps: {
        neverBundle: ['@opencode-ai/plugin'],
    },
})
