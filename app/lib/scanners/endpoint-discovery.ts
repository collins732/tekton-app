import axios from 'axios';
import * as cheerio from 'cheerio';
import { browserGet, isCloudflareBlocked } from './http-client';

/**
 * ENDPOINT DISCOVERY - Découverte automatique des endpoints
 *
 * Au lieu de tester seulement 6 endpoints hardcodés,
 * ce module découvre automatiquement TOUS les endpoints d'un site
 */

export interface DiscoveredEndpoint {
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  source: 'html_link' | 'js_api_call' | 'form_action' | 'fuzzing' | 'sitemap';
  isAPI: boolean;
}

// Patterns pour identifier des endpoints API
const API_PATTERNS = [
  /\/api\//i,
  /\/v\d+\//i,  // /v1/, /v2/, etc.
  /\/graphql/i,
  /\/rest\//i,
  /\/services\//i,
];

// Endpoints communs à fuzzer
const COMMON_ENDPOINTS = [
  // Admin
  '/admin',
  '/admin/',
  '/admin/login',
  '/admin/dashboard',
  '/administrator',
  '/backend',
  '/panel',
  '/cpanel',

  // API Admin
  '/api/admin',
  '/api/admin/users',
  '/api/admin/config',
  '/api/admin/settings',
  '/api/admin/logs',
  '/api/admin/delete',

  // API Public
  '/api/users',
  '/api/user',
  '/api/products',
  '/api/orders',
  '/api/cart',
  '/api/checkout',
  '/api/payment',
  '/api/config',
  '/api/settings',

  // API Auth
  '/api/auth',
  '/api/auth/login',
  '/api/auth/logout',
  '/api/auth/register',
  '/api/auth/forgot-password',
  '/api/auth/reset-password',

  // API Internal
  '/api/internal',
  '/api/internal/config',
  '/api/internal/debug',
  '/api/internal/health',

  // GraphQL
  '/graphql',
  '/api/graphql',

  // REST Versions
  '/api/v1',
  '/api/v2',
  '/api/v3',

  // WordPress
  '/wp-json',
  '/wp-json/wp/v2/users',
  '/wp-admin',

  // Debug/Dev
  '/debug',
  '/dev',
  '/.env',
  '/config',
];

/**
 * Point d'entrée principal - Découvre tous les endpoints d'un site
 */
export async function discoverEndpoints(target: string): Promise<DiscoveredEndpoint[]> {
  const endpoints = new Set<string>();
  const discovered: DiscoveredEndpoint[] = [];

  console.log('\n[INFO] Starting Endpoint Discovery...');
  console.log(`   Target: ${target}`);

  try {
    // 1. Crawl HTML pour trouver des liens
    console.log('\n   [HTML] [1/5] Crawling HTML links...');
    const htmlLinks = await crawlHTML(target);
    console.log(`   ✓ Found ${htmlLinks.length} links in HTML`);

    for (const link of htmlLinks) {
      if (!endpoints.has(link.url)) {
        endpoints.add(link.url);
        discovered.push(link);
      }
    }

    // 2. Analyser le JavaScript pour trouver des appels API
    console.log('\n   [JS] [2/5] Analyzing JavaScript for API calls...');
    const jsAPIs = await analyzeJavaScript(target);
    console.log(`   ✓ Found ${jsAPIs.length} API calls in JavaScript`);

    for (const api of jsAPIs) {
      if (!endpoints.has(api.url)) {
        endpoints.add(api.url);
        discovered.push(api);
      }
    }

    // 3. Analyser les formulaires
    console.log('\n   [LIST] [3/5] Analyzing forms...');
    const forms = await analyzeForms(target);
    console.log(`   ✓ Found ${forms.length} form actions`);

    for (const form of forms) {
      if (!endpoints.has(form.url)) {
        endpoints.add(form.url);
        discovered.push(form);
      }
    }

    // 4. Fuzzing d'endpoints communs
    console.log('\n   [TARGET] [4/5] Fuzzing common endpoints...');
    const fuzzed = await fuzzCommonEndpoints(target);
    console.log(`   ✓ Found ${fuzzed.length} existing endpoints via fuzzing`);

    for (const endpoint of fuzzed) {
      if (!endpoints.has(endpoint.url)) {
        endpoints.add(endpoint.url);
        discovered.push(endpoint);
      }
    }

    // 5. Chercher un sitemap
    console.log('\n   [MAP]  [5/5] Checking sitemap...');
    const sitemap = await checkSitemap(target);
    console.log(`   ✓ Found ${sitemap.length} URLs in sitemap`);

    for (const url of sitemap) {
      if (!endpoints.has(url.url)) {
        endpoints.add(url.url);
        discovered.push(url);
      }
    }

  } catch (error) {
    console.error('   [ERROR] Error during endpoint discovery:', error);
  }

  // Filtrer et trier
  const filtered = discovered.filter(e => {
    // Ignorer les assets statiques
    const isAsset = /\.(jpg|jpeg|png|gif|css|js|ico|svg|woff|woff2|ttf)$/i.test(e.url);
    return !isAsset;
  });

  // Séparer les APIs des pages normales
  const apis = filtered.filter(e => e.isAPI);
  const pages = filtered.filter(e => !e.isAPI);

  console.log('\n   [OK] Discovery completed!');
  console.log(`   [STATS] Total endpoints found: ${filtered.length}`);
  console.log(`      - APIs: ${apis.length}`);
  console.log(`      - Pages: ${pages.length}`);

  return filtered;
}

/**
 * [1] Crawle le HTML pour extraire tous les liens
 */
async function crawlHTML(target: string): Promise<DiscoveredEndpoint[]> {
  const endpoints: DiscoveredEndpoint[] = [];

  try {
    const response = await browserGet(target, { addDelay: false });

    if (response.status !== 200 || isCloudflareBlocked(response)) {
      return endpoints;
    }

    const $ = cheerio.load(response.data);
    const baseUrl = new URL(target);

    // Extraire tous les liens <a href="...">
    $('a[href]').each((_, element) => {
      const href = $(element).attr('href');
      if (!href) return;

      try {
        const url = new URL(href, target);

        // Seulement les URLs du même domaine
        if (url.hostname === baseUrl.hostname) {
          const isAPI = API_PATTERNS.some(pattern => pattern.test(url.pathname));

          endpoints.push({
            url: url.href,
            method: 'GET',
            source: 'html_link',
            isAPI,
          });
        }
      } catch (error) {
        // URL invalide, ignorer
      }
    });

  } catch (error) {
    // Erreur de crawling, continuer
  }

  return endpoints;
}

/**
 * [2] Analyse le JavaScript pour trouver des appels API
 */
async function analyzeJavaScript(target: string): Promise<DiscoveredEndpoint[]> {
  const endpoints: DiscoveredEndpoint[] = [];

  try {
    const response = await browserGet(target, { addDelay: false });

    if (response.status !== 200 || isCloudflareBlocked(response)) {
      return endpoints;
    }

    const $ = cheerio.load(response.data);
    const baseUrl = new URL(target);

    // Récupérer tous les scripts inline
    const scripts: string[] = [];

    $('script').each((_, element) => {
      const scriptContent = $(element).html();
      if (scriptContent) {
        scripts.push(scriptContent);
      }

      // Scripts externes
      const src = $(element).attr('src');
      if (src) {
        // On pourrait aussi crawler les scripts externes
        // mais ça prendrait trop de temps
      }
    });

    const allScripts = scripts.join('\n');

    // Patterns pour détecter des appels API
    const apiCallPatterns = [
      // fetch('/api/users')
      /fetch\s*\(\s*['"`]([^'"`]+)['"`]/g,

      // axios.get('/api/users')
      /axios\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/g,

      // $.ajax({ url: '/api/users' })
      /url\s*:\s*['"`]([^'"`]+)['"`]/g,

      // '/api/users'
      /['"`](\/api\/[^'"`]+)['"`]/g,
    ];

    for (const pattern of apiCallPatterns) {
      let match;
      while ((match = pattern.exec(allScripts)) !== null) {
        let apiPath = match[1] || match[2];
        if (!apiPath) continue;

        try {
          const url = new URL(apiPath, target);

          if (url.hostname === baseUrl.hostname) {
            const isAPI = API_PATTERNS.some(p => p.test(url.pathname));

            endpoints.push({
              url: url.href,
              method: 'GET', // On ne peut pas déterminer la méthode
              source: 'js_api_call',
              isAPI: true, // Les appels JS sont généralement des APIs
            });
          }
        } catch (error) {
          // URL invalide
        }
      }
    }

  } catch (error) {
    // Erreur d'analyse
  }

  // Dédupliquer
  const unique = Array.from(new Map(endpoints.map(e => [e.url, e])).values());
  return unique;
}

/**
 * [3] Analyse les formulaires pour trouver les actions
 */
async function analyzeForms(target: string): Promise<DiscoveredEndpoint[]> {
  const endpoints: DiscoveredEndpoint[] = [];

  try {
    const response = await browserGet(target, { addDelay: false });

    if (response.status !== 200 || isCloudflareBlocked(response)) {
      return endpoints;
    }

    const $ = cheerio.load(response.data);
    const baseUrl = new URL(target);

    $('form').each((_, element) => {
      const action = $(element).attr('action');
      const method = ($(element).attr('method') || 'GET').toUpperCase() as any;

      if (action) {
        try {
          const url = new URL(action, target);

          if (url.hostname === baseUrl.hostname) {
            const isAPI = API_PATTERNS.some(p => p.test(url.pathname));

            endpoints.push({
              url: url.href,
              method,
              source: 'form_action',
              isAPI,
            });
          }
        } catch (error) {
          // URL invalide
        }
      }
    });

  } catch (error) {
    // Erreur d'analyse
  }

  return endpoints;
}

/**
 * [4] Fuzzing d'endpoints communs (découverte par bruteforce)
 */
async function fuzzCommonEndpoints(target: string): Promise<DiscoveredEndpoint[]> {
  const endpoints: DiscoveredEndpoint[] = [];
  const baseUrl = new URL(target);

  // Limiter le nombre de requêtes pour ne pas DDoS le site
  const maxTests = 30; // Tester seulement les 30 premiers
  const endpointsToTest = COMMON_ENDPOINTS.slice(0, maxTests);

  for (const path of endpointsToTest) {
    try {
      const testUrl = `${baseUrl.origin}${path}`;

      const response = await browserGet(testUrl, { addDelay: true, timeout: 5000 });

      // Si l'endpoint existe (pas 404) et pas bloqué
      if (response.status !== 404 && !isCloudflareBlocked(response)) {
        const isAPI = API_PATTERNS.some(p => p.test(path));

        endpoints.push({
          url: testUrl,
          method: 'GET',
          source: 'fuzzing',
          isAPI,
        });
      }

    } catch (error) {
      // Endpoint n'existe pas ou erreur réseau
    }
  }

  return endpoints;
}

/**
 * [5] Cherche un sitemap.xml
 */
async function checkSitemap(target: string): Promise<DiscoveredEndpoint[]> {
  const endpoints: DiscoveredEndpoint[] = [];
  const baseUrl = new URL(target);

  const sitemapPaths = [
    '/sitemap.xml',
    '/sitemap_index.xml',
    '/sitemap-index.xml',
  ];

  for (const path of sitemapPaths) {
    try {
      const sitemapUrl = `${baseUrl.origin}${path}`;

      const response = await browserGet(sitemapUrl, { addDelay: false, timeout: 5000 });

      if (response.status === 200 && !isCloudflareBlocked(response)) {
        // Parser le XML (simpliste)
        const urls = response.data.match(/<loc>([^<]+)<\/loc>/g) || [];

        for (const urlMatch of urls) {
          const url = urlMatch.replace(/<\/?loc>/g, '');

          try {
            const parsedUrl = new URL(url);

            if (parsedUrl.hostname === baseUrl.hostname) {
              const isAPI = API_PATTERNS.some(p => p.test(parsedUrl.pathname));

              endpoints.push({
                url: parsedUrl.href,
                method: 'GET',
                source: 'sitemap',
                isAPI,
              });
            }
          } catch (error) {
            // URL invalide
          }
        }

        break; // Sitemap trouvé, pas besoin de chercher les autres
      }

    } catch (error) {
      // Sitemap n'existe pas
    }
  }

  return endpoints;
}

/**
 * Utilitaire : Sleep
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Filtre les endpoints pour ne garder que les plus intéressants
 */
export function filterInterestingEndpoints(endpoints: DiscoveredEndpoint[]): DiscoveredEndpoint[] {
  // Priorité aux APIs et aux endpoints sensibles
  const priorityKeywords = [
    'admin',
    'api',
    'auth',
    'login',
    'user',
    'config',
    'setting',
    'delete',
    'internal',
    'debug',
  ];

  return endpoints.sort((a, b) => {
    const aScore = priorityKeywords.filter(k => a.url.toLowerCase().includes(k)).length;
    const bScore = priorityKeywords.filter(k => b.url.toLowerCase().includes(k)).length;

    // Trier par score décroissant
    return bScore - aScore;
  });
}
