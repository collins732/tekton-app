import axios, { AxiosRequestConfig, AxiosResponse } from 'axios';

/**
 * HTTP CLIENT ANTI-WAF
 *
 * Ce module permet de faire des requêtes HTTP qui imitent un vrai navigateur
 * pour bypasser les protections WAF comme Cloudflare.
 *
 * USAGE AUTORISÉ UNIQUEMENT : Tests de sécurité sur vos propres applications
 */

// User-Agents réalistes de vrais navigateurs
const USER_AGENTS = [
  // Chrome Windows
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
  // Chrome Mac
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  // Firefox Windows
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
  // Firefox Mac
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
  // Safari Mac
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
  // Edge Windows
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
];

// Headers réalistes d'un navigateur
function getBrowserHeaders(referer?: string): Record<string, string> {
  const userAgent = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];

  return {
    'User-Agent': userAgent,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': referer ? 'same-origin' : 'none',
    'Sec-Fetch-User': '?1',
    'Cache-Control': 'max-age=0',
    ...(referer && { 'Referer': referer }),
  };
}

// Délai aléatoire entre les requêtes (imite le comportement humain)
function randomDelay(min: number = 100, max: number = 500): Promise<void> {
  const delay = Math.floor(Math.random() * (max - min + 1)) + min;
  return new Promise(resolve => setTimeout(resolve, delay));
}

// Session avec cookies persistants
let sessionCookies: Record<string, string> = {};

/**
 * Effectue une requête GET avec headers de navigateur
 */
export async function browserGet(
  url: string,
  options: {
    timeout?: number;
    referer?: string;
    followRedirects?: boolean;
    addDelay?: boolean;
  } = {}
): Promise<AxiosResponse> {
  const { timeout = 10000, referer, followRedirects = true, addDelay = true } = options;

  if (addDelay) {
    await randomDelay(50, 200);
  }

  const config: AxiosRequestConfig = {
    timeout,
    maxRedirects: followRedirects ? 5 : 0,
    validateStatus: () => true,
    headers: {
      ...getBrowserHeaders(referer),
      ...(Object.keys(sessionCookies).length > 0 && {
        'Cookie': Object.entries(sessionCookies).map(([k, v]) => `${k}=${v}`).join('; ')
      }),
    },
    // Décompression automatique
    decompress: true,
  };

  try {
    const response = await axios.get(url, config);

    // Sauvegarder les cookies de la réponse
    saveCookies(response);

    return response;
  } catch (error: any) {
    // Si erreur SSL, réessayer sans vérification (pour les tests internes)
    if (error.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || error.code === 'CERT_HAS_EXPIRED') {
      const response = await axios.get(url, {
        ...config,
        httpsAgent: new (require('https').Agent)({ rejectUnauthorized: false })
      });
      saveCookies(response);
      return response;
    }
    throw error;
  }
}

/**
 * Effectue une requête POST avec headers de navigateur
 */
export async function browserPost(
  url: string,
  data: Record<string, string> | string,
  options: {
    timeout?: number;
    referer?: string;
    contentType?: 'form' | 'json';
    addDelay?: boolean;
  } = {}
): Promise<AxiosResponse> {
  const { timeout = 10000, referer, contentType = 'form', addDelay = true } = options;

  if (addDelay) {
    await randomDelay(100, 300);
  }

  const headers = {
    ...getBrowserHeaders(referer),
    'Content-Type': contentType === 'json'
      ? 'application/json'
      : 'application/x-www-form-urlencoded',
    ...(Object.keys(sessionCookies).length > 0 && {
      'Cookie': Object.entries(sessionCookies).map(([k, v]) => `${k}=${v}`).join('; ')
    }),
  };

  // Formater les données
  let formattedData: string;
  if (typeof data === 'string') {
    formattedData = data;
  } else if (contentType === 'json') {
    formattedData = JSON.stringify(data);
  } else {
    formattedData = new URLSearchParams(data).toString();
  }

  const config: AxiosRequestConfig = {
    timeout,
    validateStatus: () => true,
    headers,
    decompress: true,
  };

  try {
    const response = await axios.post(url, formattedData, config);
    saveCookies(response);
    return response;
  } catch (error: any) {
    if (error.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || error.code === 'CERT_HAS_EXPIRED') {
      const response = await axios.post(url, formattedData, {
        ...config,
        httpsAgent: new (require('https').Agent)({ rejectUnauthorized: false })
      });
      saveCookies(response);
      return response;
    }
    throw error;
  }
}

/**
 * Sauvegarde les cookies de la réponse
 */
function saveCookies(response: AxiosResponse): void {
  const setCookieHeader = response.headers['set-cookie'];
  if (setCookieHeader) {
    setCookieHeader.forEach((cookie: string) => {
      const [nameValue] = cookie.split(';');
      const [name, value] = nameValue.split('=');
      if (name && value) {
        sessionCookies[name.trim()] = value.trim();
      }
    });
  }
}

/**
 * Réinitialise la session (cookies)
 */
export function resetSession(): void {
  sessionCookies = {};
}

/**
 * Vérifie si la réponse est un blocage Cloudflare
 */
export function isCloudflareBlocked(response: AxiosResponse): boolean {
  const html = response.data?.toString() || '';
  const status = response.status;

  // Status codes Cloudflare
  if (status === 403 || status === 503 || status === 1020) {
    return true;
  }

  // Patterns Cloudflare dans le HTML
  const cloudflarePatterns = [
    /cloudflare/i,
    /cf-ray/i,
    /checking your browser/i,
    /please wait while we verify/i,
    /attention required/i,
    /ray id:/i,
    /__cf_chl/i,
    /challenge-platform/i,
  ];

  return cloudflarePatterns.some(pattern => pattern.test(html));
}

/**
 * Récupère le contenu en contournant les challenges JS simples
 * Note: Ne fonctionne pas pour les challenges avancés (CAPTCHA)
 */
export async function fetchWithRetry(
  url: string,
  maxRetries: number = 3
): Promise<AxiosResponse | null> {
  for (let i = 0; i < maxRetries; i++) {
    try {
      // Délai croissant entre les tentatives
      if (i > 0) {
        await randomDelay(1000 * i, 2000 * i);
      }

      const response = await browserGet(url, { addDelay: true });

      // Si pas bloqué, retourner
      if (!isCloudflareBlocked(response)) {
        return response;
      }

      console.log(`   [WARN] Cloudflare detected, retry ${i + 1}/${maxRetries}...`);

    } catch (error) {
      console.log(`   [ERROR] Request failed, retry ${i + 1}/${maxRetries}...`);
    }
  }

  return null;
}

/**
 * Wrapper pour les tests de vulnérabilités
 */
export async function testPayload(
  url: string,
  method: 'GET' | 'POST',
  params: Record<string, string>,
  options: { referer?: string } = {}
): Promise<{ response: AxiosResponse | null; blocked: boolean }> {
  try {
    let response: AxiosResponse;

    if (method === 'POST') {
      response = await browserPost(url, params, { referer: options.referer });
    } else {
      const testUrl = new URL(url);
      Object.entries(params).forEach(([key, value]) => {
        testUrl.searchParams.set(key, value);
      });
      response = await browserGet(testUrl.href, { referer: options.referer });
    }

    const blocked = isCloudflareBlocked(response);

    return { response: blocked ? null : response, blocked };
  } catch (error) {
    return { response: null, blocked: true };
  }
}
