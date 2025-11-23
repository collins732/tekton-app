import axios from 'axios';
import * as cheerio from 'cheerio';
import { Vulnerability } from '../types';
import { discoverEndpoints } from './endpoint-discovery';
import { discoverParameters, generateTestUrls, summarizeParameters } from './parameter-discovery';

// ============================================================================
// XSS SCANNER - OWASP A03:2021 (Injection) - Cross-Site Scripting
// ============================================================================

/**
 * À QUOI SERT CE SCANNER :
 *
 * Le Cross-Site Scripting (XSS) est une vulnérabilité où un attaquant peut
 * injecter du code JavaScript malveillant dans une page web.
 *
 * EXEMPLE D'ATTAQUE :
 * Input normal:   name = "Jean"
 * Attaque XSS:    name = "<script>alert(document.cookie)</script>"
 * Résultat:       La page affiche: Hello <script>alert(document.cookie)</script>
 *                 → Le script s'exécute dans le navigateur de la victime
 *
 * RISQUES :
 * - Vol de cookies/sessions (piratage de compte)
 * - Redirection vers sites malveillants (phishing)
 * - Modification de la page (défaçage)
 * - Keylogging (enregistrement des frappes clavier)
 * - Installation de malware
 *
 * TYPES DE XSS :
 * 1. Reflected XSS : Le payload est dans l'URL et reflété immédiatement
 * 2. Stored XSS : Le payload est stocké en base de données (plus dangereux)
 * 3. DOM-based XSS : Le payload manipule le DOM côté client
 *
 * COMMENT DÉTECTER :
 * - Envoyer des payloads JavaScript malveillants
 * - Vérifier s'ils sont reflétés SANS encodage
 * - Vérifier si le contexte HTML permet l'exécution
 *
 * [WARNING] IMPORTANT ANTI-FAUX POSITIFS :
 * Le payload doit être reflété ET non-encodé pour être vulnérable:
 *   VULNÉRABLE:     <script>alert(1)</script>
 *   PAS VULNÉRABLE: &lt;script&gt;alert(1)&lt;/script&gt;
 */

// Payloads XSS (ordonnés par contexte)
const XSS_PAYLOADS = [
  // Basiques - Script tags
  '<script>alert(1)</script>',
  '<script>alert(String.fromCharCode(88,83,83))</script>',

  // Breaking out of attributes
  '"><script>alert(1)</script>',
  '\'-alert(1)-\'',
  '"><img src=x onerror=alert(1)>',

  // Event handlers
  '<img src=x onerror=alert(1)>',
  '<svg/onload=alert(1)>',
  '<body onload=alert(1)>',
  '<iframe src="javascript:alert(1)">',

  // Sans brackets (pour filtres simples)
  'javascript:alert(1)',
  'onerror=alert(1)',

  // Polyglot (fonctionne dans plusieurs contextes)
  'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//',
];

// Patterns de détection d'encodage (= pas vulnérable)
const ENCODING_PATTERNS = {
  htmlEntities: /&lt;|&gt;|&quot;|&#39;|&#x2F;/,
  urlEncoded: /%3C|%3E|%22|%27/i,
  unicodeEscaped: /\\u003c|\\u003e/i,
  jsEscaped: /\\x3c|\\x3e/i,
};

// Contextes HTML dangereux (où le XSS peut s'exécuter)
const DANGEROUS_CONTEXTS = [
  'script',  // <script>PAYLOAD</script>
  'style',   // <style>PAYLOAD</style>
  'href',    // <a href="PAYLOAD">
  'src',     // <img src="PAYLOAD">
  'onclick', // <div onclick="PAYLOAD">
  'onerror', // <img onerror="PAYLOAD">
  'onload',  // <body onload="PAYLOAD">
];

/**
 * Point d'entrée principal du scanner XSS
 * [OK] VERSION 2.0: Découverte automatique de TOUS les paramètres
 */
export async function scanXSS(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];

  console.log('\n[TARGET] Starting XSS (Cross-Site Scripting) scan...');
  console.log('   [INFO] Discovering all endpoints and parameters automatically...');

  try {
    // [OK] ÉTAPE 1: Découvrir TOUS les endpoints du site
    const allEndpoints = await discoverEndpoints(target);
    console.log(`   [STATS] Found ${allEndpoints.length} total endpoints`);

    // Limiter à 30 endpoints pour ne pas surcharger (priorité aux pages avec params)
    const endpointsWithParams = allEndpoints.filter(e => e.url.includes('?'));
    const endpointsToScan = [
      ...endpointsWithParams.slice(0, 20),
      ...allEndpoints.filter(e => !e.url.includes('?')).slice(0, 10)
    ].map(e => e.url);

    console.log(`   [TARGET] Will scan ${endpointsToScan.length} endpoints`);

    // [OK] ÉTAPE 2: Découvrir TOUS les paramètres testables
    const allParameters = await discoverParameters(endpointsToScan);
    summarizeParameters(allParameters);

    if (allParameters.length === 0) {
      console.log('   [WARNING]  No testable parameters found via auto-discovery');
      console.log('   [FALLBACK] Falling back to testing the target URL directly...');

      // FALLBACK: Tester au moins l'URL donnée
      return await scanXSS_Fallback(target);
    }

    // Limiter à 50 paramètres max pour la performance
    const parametersToTest = allParameters.slice(0, 50);
    console.log(`   [TEST] Testing ${parametersToTest.length} parameters for XSS...`);

    // [OK] ÉTAPE 3: Tester CHAQUE paramètre avec les payloads XSS
    let tested = 0;
    for (const param of parametersToTest) {
      tested++;

      // Log progression
      if (tested % 10 === 0) {
        console.log(`   [PROGRESS] Progress: ${tested}/${parametersToTest.length} parameters tested...`);
      }

      let foundVuln = false;

      // Tester avec chaque payload
      for (const payload of XSS_PAYLOADS.slice(0, 5)) { // Limiter à 5 payloads pour performance
        try {
          const testRequest = generateTestUrls(param, payload);

          let response;
          if (testRequest.method === 'POST' && testRequest.data) {
            response = await axios.post(testRequest.url, testRequest.data, {
              timeout: 5000,
              validateStatus: () => true,
              headers: {
                'User-Agent': 'VulnScanner/2.0',
                'Content-Type': 'application/x-www-form-urlencoded',
              },
            });
          } else {
            response = await axios.get(testRequest.url, {
              timeout: 5000,
              validateStatus: () => true,
              headers: { 'User-Agent': 'VulnScanner/2.0' },
            });
          }

          // [OK] DÉTECTION STRICTE : Vérifier réflexion + encodage
          const reflectionAnalysis = analyzeReflection(payload, response.data);

          if (reflectionAnalysis.vulnerable) {
            vulnerabilities.push({
              type: 'xss',
              severity: 'high',
              title: 'Reflected XSS Vulnerability',
              description: `The application reflects user input without proper sanitization. The parameter "${param.paramName}" is vulnerable to Cross-Site Scripting (XSS) attacks, allowing attackers to execute arbitrary JavaScript in users' browsers.`,
              location: param.url,
              evidence: `Payload: ${payload}\nReflected in context: ${reflectionAnalysis.context || 'HTML body'}\nParameter: ${param.paramName} (${param.paramType})\nMethod: ${param.method}`,
            });

            console.log(`   [CRITICAL] HIGH: XSS found in "${param.paramName}" at ${param.url}`);
            foundVuln = true;
            break;
          }

        } catch (error) {
          // Timeout ou erreur réseau = continuer
        }

        // Petit délai pour ne pas surcharger
        await sleep(50);
      }

      if (!foundVuln && tested <= 10) {
        console.log(`   [OK] Parameter "${param.paramName}" at ${param.url.substring(0, 60)}... appears safe`);
      }
    }

    console.log(`\n   [OK] XSS scan completed: ${vulnerabilities.length} vulnerabilities found\n`);

  } catch (error) {
    console.error('   [ERROR] Error scanning XSS:', error);
  }

  return vulnerabilities;
}

/**
 * Utilitaire : Sleep
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * FALLBACK: Scanner XSS classique si le parameter discovery échoue
 */
async function scanXSS_Fallback(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];

  console.log('   [LIST] Using fallback mode - testing target URL directly');

  try {
    const response = await axios.get(target, {
      timeout: 10000,
      validateStatus: () => true,
      headers: { 'User-Agent': 'VulnScanner/2.0' },
    });

    if (response.status !== 200) {
      return vulnerabilities;
    }

    const $ = cheerio.load(response.data);

    // Tester les formulaires de la page
    const forms = $('form');
    for (let i = 0; i < forms.length; i++) {
      const form = $(forms[i]);
      const action = form.attr('action') || '';
      const method = (form.attr('method') || 'get').toLowerCase();
      const inputs = form.find('input, textarea').toArray();
      const inputNames = inputs
        .map(input => $(input).attr('name'))
        .filter((name): name is string => !!name);

      if (inputNames.length === 0) continue;

      const formUrl = new URL(action, target).href;

      for (const payload of XSS_PAYLOADS.slice(0, 3)) {
        const testResult = await testXSSPayload(formUrl, method, inputNames, payload);
        if (testResult.vulnerable) {
          vulnerabilities.push({
            type: 'xss',
            severity: 'high',
            title: 'Reflected XSS Vulnerability',
            description: `The application reflects user input without proper sanitization. The parameter "${testResult.parameter}" is vulnerable to Cross-Site Scripting (XSS) attacks, allowing attackers to execute arbitrary JavaScript in users' browsers.`,
            location: formUrl,
            evidence: `Payload: ${payload}\nReflected in context: ${testResult.context || 'HTML body'}\nInput Field: ${testResult.parameter}`,
          });
          break;
        }
      }
    }

    // Tester les paramètres URL
    const url = new URL(target);
    const urlParams = Array.from(url.searchParams.keys());
    for (const param of urlParams) {
      for (const payload of XSS_PAYLOADS.slice(0, 3)) {
        const testUrl = new URL(target);
        testUrl.searchParams.set(param, payload);

        try {
          const testResponse = await axios.get(testUrl.href, {
            timeout: 5000,
            validateStatus: () => true,
            headers: { 'User-Agent': 'VulnScanner/2.0' },
          });

          const reflectionAnalysis = analyzeReflection(payload, testResponse.data);
          if (reflectionAnalysis.vulnerable) {
            vulnerabilities.push({
              type: 'xss',
              severity: 'high',
              title: 'Reflected XSS in URL Parameter',
              description: `The URL parameter "${param}" reflects user input without proper encoding. This allows XSS attacks through URL manipulation.`,
              location: testUrl.href,
              evidence: `Payload: ${payload}\nReflected unencoded in: ${reflectionAnalysis.context}\nParameter: ${param}`,
            });
            break;
          }
        } catch (error) {
          // Continue
        }
      }
    }
  } catch (error) {
    console.error('   [ERROR] Error in fallback mode:', error);
  }

  return vulnerabilities;
}

/**
 * Teste un payload XSS sur un formulaire
 */
async function testXSSPayload(
  url: string,
  method: string,
  params: string[],
  payload: string
): Promise<{ vulnerable: boolean; parameter?: string; context?: string }> {
  try {
    const data: Record<string, string> = {};

    // Injecter le payload dans TOUS les champs
    params.forEach(param => {
      data[param] = payload;
    });

    let response;

    if (method === 'post') {
      response = await axios.post(url, data, {
        timeout: 5000,
        validateStatus: () => true,
        headers: {
          'User-Agent': 'VulnScanner/2.0',
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      });
    } else {
      response = await axios.get(url, {
        params: data,
        timeout: 5000,
        validateStatus: () => true,
        headers: { 'User-Agent': 'VulnScanner/2.0' },
      });
    }

    // [OK] DÉTECTION STRICTE : Analyser la réflexion et l'encodage
    const reflectionAnalysis = analyzeReflection(payload, response.data);

    if (reflectionAnalysis.vulnerable) {
      return {
        vulnerable: true,
        parameter: params[0],
        context: reflectionAnalysis.context,
      };
    }

  } catch (error) {
    // Timeout ou erreur réseau = pas une vulnérabilité
  }

  return { vulnerable: false };
}

/**
 * Analyse la réflexion du payload dans la réponse
 * [OK] ANTI-FAUX POSITIFS : Vérifie l'encodage ET le contexte
 */
function analyzeReflection(
  payload: string,
  html: string
): { vulnerable: boolean; context?: string } {
  if (!html || typeof html !== 'string' || !html.includes(payload)) {
    // Payload pas reflété du tout = pas vulnérable
    return { vulnerable: false };
  }

  // 1. Vérifier si le payload est encodé
  if (isProperlyEncoded(payload, html)) {
    // Payload encodé = pas vulnérable (sécurisé)
    return { vulnerable: false };
  }

  // 2. Le payload est reflété ET non-encodé
  // Vérifier le contexte HTML pour confirmer la vulnérabilité
  const context = detectDangerousContext(payload, html);

  if (context) {
    // Reflété dans un contexte dangereux = VULNÉRABLE
    return { vulnerable: true, context };
  }

  // Reflété dans un contexte sûr (ex: dans un commentaire HTML)
  // On le considère quand même comme potentiellement vulnérable
  return { vulnerable: true, context: 'HTML body' };
}

/**
 * Vérifie si le payload a été correctement encodé
 * [OK] CLÉS ANTI-FAUX POSITIFS
 */
function isProperlyEncoded(payload: string, html: string): boolean {
  // Extraire la partie de HTML contenant le payload
  const payloadIndex = html.indexOf(payload);

  if (payloadIndex === -1) {
    // Peut-être encodé sous une autre forme
    // Vérifier les formes encodées communes

    // HTML entities
    if (ENCODING_PATTERNS.htmlEntities.test(html)) {
      const encodedPayload = payload
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');

      if (html.includes(encodedPayload)) {
        return true; // Correctement encodé en HTML entities
      }
    }

    // URL encoded
    if (ENCODING_PATTERNS.urlEncoded.test(html)) {
      const urlEncodedPayload = encodeURIComponent(payload);
      if (html.includes(urlEncodedPayload)) {
        return true; // Correctement URL-encodé
      }
    }

    // Unicode escaped
    if (ENCODING_PATTERNS.unicodeEscaped.test(html)) {
      return true; // Échappé en Unicode
    }

    // JS escaped
    if (ENCODING_PATTERNS.jsEscaped.test(html)) {
      return true; // Échappé en JS
    }
  }

  // Si on arrive ici, le payload est reflété tel quel (non encodé)
  return false;
}

/**
 * Détecte si le payload est dans un contexte HTML dangereux
 */
function detectDangerousContext(payload: string, html: string): string | null {
  const payloadIndex = html.indexOf(payload);

  if (payloadIndex === -1) {
    return null;
  }

  // Extraire 200 caractères avant le payload pour analyser le contexte
  const start = Math.max(0, payloadIndex - 200);
  const contextBefore = html.substring(start, payloadIndex).toLowerCase();

  // Vérifier chaque contexte dangereux
  for (const context of DANGEROUS_CONTEXTS) {
    // Patterns pour détecter le contexte
    const patterns = [
      new RegExp(`<${context}[^>]*$`),      // <script>PAYLOAD
      new RegExp(`${context}\\s*=\\s*["\']?$`), // onclick="PAYLOAD
      new RegExp(`<[^>]+\\s${context}\\s*=\\s*["\']?$`), // <div onclick="PAYLOAD
    ];

    for (const pattern of patterns) {
      if (pattern.test(contextBefore)) {
        return context;
      }
    }
  }

  // Vérifier si dans un tag <script> ou <style>
  if (contextBefore.includes('<script') && !contextBefore.includes('</script>')) {
    return 'script';
  }

  if (contextBefore.includes('<style') && !contextBefore.includes('</style>')) {
    return 'style';
  }

  // Si aucun contexte spécifique détecté, retourner null
  // (sera considéré comme 'HTML body' par la fonction appelante)
  return null;
}

/**
 * Détecte si le payload cause une exécution JavaScript
 * (Pour validation supplémentaire - nécessiterait un navigateur headless pour être 100% précis)
 */
function wouldExecuteInBrowser(payload: string, context: string): boolean {
  // Contextes qui permettent l'exécution JavaScript
  const executableContexts = ['script', 'onclick', 'onerror', 'onload', 'href', 'src'];

  if (executableContexts.includes(context)) {
    return true;
  }

  // Vérifier les patterns d'exécution dans le payload
  const executablePatterns = [
    /<script[^>]*>/i,
    /javascript:/i,
    /on\w+\s*=/i, // onclick=, onerror=, etc.
  ];

  return executablePatterns.some(pattern => pattern.test(payload));
}
