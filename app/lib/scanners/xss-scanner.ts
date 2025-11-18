import axios from 'axios';
import * as cheerio from 'cheerio';
import { Vulnerability } from '../types';

// Payloads XSS basiques
const XSS_PAYLOADS = [
  '<script>alert(1)</script>',
  '"><script>alert(1)</script>',
  '<img src=x onerror=alert(1)>',
  '<svg/onload=alert(1)>',
  'javascript:alert(1)',
  '<iframe src="javascript:alert(1)">',
];

/**
 * Scanne les vulnérabilités XSS basiques
 * Teste les inputs de formulaires et paramètres URL
 */
export async function scanXSS(target: string): Promise<Vulnerability[]> {
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
      for (const payload of XSS_PAYLOADS) {
        const formUrl = new URL(action, target).href;
        const testResult = await testXSSPayload(
          formUrl,
          method,
          inputNames,
          payload
        );

        if (testResult.vulnerable) {
          vulnerabilities.push({
            type: 'xss',
            severity: 'high',
            title: 'Reflected XSS Vulnerability',
            description: `The application reflects user input without proper sanitization. The parameter "${testResult.parameter}" is vulnerable to XSS attacks.`,
            location: formUrl,
            evidence: `Payload: ${payload}`,
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
      for (const payload of XSS_PAYLOADS) {
        const testUrl = new URL(target);
        testUrl.searchParams.set(param, payload);

        try {
          const testResponse = await axios.get(testUrl.href, {
            timeout: 5000,
            headers: { 'User-Agent': 'VulnScanner/1.0' },
          });

          // Vérifier si le payload est reflété dans la réponse
          if (testResponse.data.includes(payload)) {
            vulnerabilities.push({
              type: 'xss',
              severity: 'high',
              title: 'Reflected XSS in URL Parameter',
              description: `The URL parameter "${param}" reflects user input without sanitization.`,
              location: testUrl.href,
              evidence: `Payload: ${payload}`,
            });
            break;
          }
        } catch (error) {
          // Ignorer les erreurs de requête
        }
      }
    }

  } catch (error) {
    console.error('Error scanning XSS:', error);
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
): Promise<{ vulnerable: boolean; parameter?: string }> {
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

    // Vérifier si le payload est reflété dans la réponse
    if (response.data.includes(payload)) {
      return {
        vulnerable: true,
        parameter: params[0],
      };
    }
  } catch (error) {
    // Ignorer les erreurs
  }

  return { vulnerable: false };
}
