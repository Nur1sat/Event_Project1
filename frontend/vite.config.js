import { defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const isProduction = mode === 'production'
  
  // Backend URL configuration
  const backendUrl = env.VITE_API_URL || (isProduction 
    ? 'http://146.103.117.133:8007' 
    : 'http://localhost:8000')
  
  // Frontend port
  const frontendPort = parseInt(env.VITE_PORT || '5176')

  return {
    plugins: [vue({
      script: {
        defineModel: true,
        propsDestructure: true
      }
    })],
    server: {
      port: frontendPort,
      host: '0.0.0.0',
      proxy: {
        '/api': {
          target: isProduction ? backendUrl : 'http://localhost:8000',
          changeOrigin: true,
          secure: false
        }
      },
      fs: {
        strict: false
      }
    },
    define: {
      __API_URL__: JSON.stringify(backendUrl)
    },
    optimizeDeps: {
      include: ['three', 'vue'],
      exclude: []
    },
    build: {
      commonjsOptions: {
        include: [/three/, /node_modules/]
      },
      rollupOptions: {
        output: {
          manualChunks: undefined
        }
      }
    },
    resolve: {
      alias: {
        '@': '/src'
      }
    }
  }
})

