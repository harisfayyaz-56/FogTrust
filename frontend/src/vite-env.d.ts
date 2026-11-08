/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** "true" starts the dashboard in offline demo mode. Defaults to real mode. */
  readonly VITE_USE_MOCK?: string;
  /** Optional absolute broker URL. Leave empty to use the Vite /api proxy. */
  readonly VITE_API_BASE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
