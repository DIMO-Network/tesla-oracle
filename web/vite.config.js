import { defineConfig } from 'vite';
import { resolve } from 'path';
import mkcert from 'vite-plugin-mkcert';
import tailwindcss from '@tailwindcss/vite'
import tsconfigPaths from "vite-tsconfig-paths";
import path from "node:path";

export default defineConfig({
    plugins: [
        mkcert({
            keyPath: 'key.pem',
            certFileName: 'cert.pem',
            savePath: path.resolve(process.cwd(), '.mkcert'),
            hosts: ['localtesla.dimo.org']
        }),
        tsconfigPaths(),
        tailwindcss(),
    ],
    server: {
        port: 4443, // Use custom port, e.g., 3000
        host: 'localtesla.dimo.org',
        https: true,
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