import { defineConfig } from 'vite';
import { resolve } from 'path';
import tailwindcss from '@tailwindcss/vite'
import tsconfigPaths from "vite-tsconfig-paths";

export default defineConfig({
    plugins: [
        tsconfigPaths(),
        tailwindcss(),
    ],
    server: {
        port: 4444, // Use custom port, e.g., 3000
    },
    resolve: {
        alias: {
            events: 'events'
        }
    },
    build: {
        chunkSizeWarningLimit: 1000,
        rollupOptions: {
            // Define multiple entry points
            input: {
                main: resolve(__dirname, 'index.html'),
            }
        }
    },
});