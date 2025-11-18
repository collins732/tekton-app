import axios from 'axios';
import * as cheerio from 'cheerio';
import { Vulnerability } from '../types';

// Payloads SQL injection basiques
const SQLI_PAYLOADS = [
  "' OR '1'='1",
  "' OR '1'='1' --",
  "' OR '1'='1' /*",
  "admin' --",
  "admin' #",
  "' UNION SELECT NULL--",
  "1' AND '1'='1",
  "' AND 1=1--",
];

// Patterns d'erreur SQL
const ERROR_PATTERNS = [
  /SQL syntax.*MySQL/i,
  /Warning.*mysql_/i,
  /valid MySQL result/i,
  /MySqlClient\./i,
  /PostgreSQL.*ERROR/i,
  /Warning.*pg_/i,
  /valid PostgreSQL result/i,
  /Npgsql\./i,
  /Driver.*SQL.*Server/i,
  /OLE DB.*SQL Server/i,
  /SQLServer JDBC Driver/i,
  /SqlException/i,
  /Oracle error/i,
  /Oracle.*Driver/i,
  /Warning.*oci_/i,
  /Warning.*ora_/i,
];

/**
 * Scanne les vulnérabilités SQL Injection basiques
 * Teste les inputs et paramètres URL
 */
export async function scanSQLi(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];

  try {
    // 1. Récupérer la page
    const response = await axios.get(target, {
      timeout: 10000,
      headers: { 'User-Agent': 'VulnScanner/1.0' },
    });

    const $ = cheerio.load(response.data);

    // 2. Trouver tous les formulaires
    const forms = $('form');

    for (let i = 0; i < forms.length; i++) {
      const form = $(forms[i]);
      const action = form.attr('action') || '';
      const method = (form.attr('method') || 'get').toLowerCase();

      // Récupérer tous les inputs
      const inputs = form.find('input, textarea').toArray();
      const inputNames = inputs
        .map(input => $(input).attr('name'))
        .filter((name): name is string => !!name);

      if (inputNames.length === 0) continue;

      // Tester chaque payload
      for (const payload of SQLI_PAYLOADS) {
        const formUrl = new URL(action, target).href;
        const testResult = await testSQLiPayload(
          formUrl,
          method,
          inputNames,
          payload
        );

        if (testResult.vulnerable) {
          vulnerabilities.push({
            type: 'sqli',
            severity: 'critical',
            title: 'SQL Injection Vulnerability',
            description: `The application is vulnerable to SQL injection. The parameter "${testResult.parameter}" does not properly sanitize user input.`,
            location: formUrl,
            evidence: `Payload: ${payload}\nError: ${testResult.error}`,
          });

          // Une seule vulnérabilité par formulaire suffit
          break;
        }
      }
    }

    // 3. Tester les paramètres URL (si présents)
    const url = new URL(target);
    const urlParams = Array.from(url.searchParams.keys());

    for (const param of urlParams) {
      for (const payload of SQLI_PAYLOADS) {
        const testUrl = new URL(target);
        testUrl.searchParams.set(param, payload);

        try {
          const testResponse = await axios.get(testUrl.href, {
            timeout: 5000,
            headers: { 'User-Agent': 'VulnScanner/1.0' },
          });

          // Vérifier les erreurs SQL dans la réponse
          const sqlError = detectSQLError(testResponse.data);
          if (sqlError) {
            vulnerabilities.push({
              type: 'sqli',
              severity: 'critical',
              title: 'SQL Injection in URL Parameter',
              description: `The URL parameter "${param}" is vulnerable to SQL injection.`,
              location: testUrl.href,
              evidence: `Payload: ${payload}\nError: ${sqlError}`,
            });
            break;
          }
        } catch (error) {
          // Ignorer les erreurs de requête
        }
      }
    }

  } catch (error) {
    console.error('Error scanning SQLi:', error);
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
    params.forEach(param => {
      data[param] = payload;
    });

    let response;
    if (method === 'post') {
      response = await axios.post(url, data, {
        timeout: 5000,
        headers: { 'User-Agent': 'VulnScanner/1.0' },
      });
    } else {
      response = await axios.get(url, {
        params: data,
        timeout: 5000,
        headers: { 'User-Agent': 'VulnScanner/1.0' },
      });
    }

    // Vérifier les erreurs SQL
    const sqlError = detectSQLError(response.data);
    if (sqlError) {
      return {
        vulnerable: true,
        parameter: params[0],
        error: sqlError,
      };
    }
  } catch (error) {
    // Ignorer les erreurs de requête
  }

  return { vulnerable: false };
}

/**
 * Détecte les erreurs SQL dans une réponse
 */
function detectSQLError(html: string): string | null {
  for (const pattern of ERROR_PATTERNS) {
    const match = html.match(pattern);
    if (match) {
      return match[0];
    }
  }
  return null;
}
