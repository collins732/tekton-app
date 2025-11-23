import axios from 'axios';
import { Vulnerability } from '../types';

/**
 * SECURITY HEADERS SCANNER - Version hybride
 *
 * Combine la validation approfondie avec des vérifications supplémentaires:
 * - Headers de sécurité manquants ou mal configurés
 * - Vérification HTTPS
 * - Validation des cookies
 */

// Security headers to check
const REQUIRED_HEADERS = {
  'x-frame-options': {
    name: 'X-Frame-Options',
    severity: 'high' as const,
    validValues: ['DENY', 'SAMEORIGIN'],
  },
  'content-security-policy': {
    name: 'Content-Security-Policy',
    severity: 'high' as const,
    validValues: null, // Any CSP is better than none
  },
  'strict-transport-security': {
    name: 'Strict-Transport-Security',
    severity: 'high' as const,
    validValues: null, // Check for presence and min max-age
  },
  'x-content-type-options': {
    name: 'X-Content-Type-Options',
    severity: 'medium' as const,
    validValues: ['nosniff'],
  },
  'x-xss-protection': {
    name: 'X-XSS-Protection',
    severity: 'low' as const,
    validValues: ['1', '1; mode=block'],
  },
  'referrer-policy': {
    name: 'Referrer-Policy',
    severity: 'low' as const,
    validValues: null, // Any policy is better than none
  },
  'permissions-policy': {
    name: 'Permissions-Policy',
    severity: 'low' as const,
    validValues: null,
  },
};

/**
 * Scanne les headers de sécurité manquants ou mal configurés
 */
export async function scanSecurityHeaders(target: string, verbose: boolean = false): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];

  if (verbose) {
    console.log('\n[Security Headers] Starting scan...');
  }

  try {
    // Faire une requête HEAD pour récupérer les headers (plus efficace)
    const response = await axios.head(target, {
      timeout: 10000,
      headers: { 'User-Agent': 'VulnScanner/2.0' },
      maxRedirects: 5,
      validateStatus: () => true, // Ne pas rejeter les erreurs HTTP
    });

    const headers = response.headers;

    if (verbose) {
      console.log(`   [OK] Target responded with status ${response.status}`);
      console.log('   [INFO] Checking security headers...');
    }

    // Vérifier X-Frame-Options
    const xFrameOptions = headers['x-frame-options'];
    if (!xFrameOptions) {
      vulnerabilities.push({
        type: 'security-header',
        severity: 'high',
        title: 'Missing X-Frame-Options Header',
        description: 'The X-Frame-Options header is not set. This makes the site vulnerable to clickjacking attacks where an attacker can embed the page in an iframe.',
        location: target,
        evidence: 'Header: X-Frame-Options is missing\nRecommendation: Add "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN"',
      });
      if (verbose) console.log('   [MISSING] X-Frame-Options');
    } else if (!['DENY', 'SAMEORIGIN'].includes(xFrameOptions.toUpperCase())) {
      vulnerabilities.push({
        type: 'security-header',
        severity: 'medium',
        title: 'Weak X-Frame-Options Configuration',
        description: `The X-Frame-Options header is set to "${xFrameOptions}" which may not provide adequate protection against clickjacking.`,
        location: target,
        evidence: `Current value: ${xFrameOptions}\nRecommendation: Use "DENY" or "SAMEORIGIN"`,
      });
      if (verbose) console.log(`   [WEAK] X-Frame-Options = ${xFrameOptions}`);
    } else if (verbose) {
      console.log(`   [OK] Present: X-Frame-Options = ${xFrameOptions}`);
    }

    // Vérifier Content-Security-Policy
    const csp = headers['content-security-policy'];
    if (!csp) {
      vulnerabilities.push({
        type: 'security-header',
        severity: 'high',
        title: 'Missing Content-Security-Policy Header',
        description: 'The Content-Security-Policy (CSP) header is missing. CSP helps prevent XSS attacks, clickjacking, and other code injection attacks.',
        location: target,
        evidence: 'Header: Content-Security-Policy is missing\nRecommendation: Implement a CSP policy appropriate for your application',
      });
      if (verbose) console.log('   [MISSING] Content-Security-Policy');
    } else if (csp.includes('unsafe-inline') || csp.includes('unsafe-eval')) {
      vulnerabilities.push({
        type: 'security-header',
        severity: 'medium',
        title: 'Weak Content-Security-Policy Configuration',
        description: 'The CSP header contains "unsafe-inline" or "unsafe-eval" which weakens XSS protection.',
        location: target,
        evidence: `Current CSP: ${csp}\nRecommendation: Remove "unsafe-inline" and "unsafe-eval" directives`,
      });
      if (verbose) console.log('   [WEAK] CSP allows unsafe-inline or unsafe-eval');
    } else if (verbose) {
      console.log(`   [OK] Present: Content-Security-Policy`);
    }

    // Vérifier Strict-Transport-Security (HSTS)
    const hsts = headers['strict-transport-security'];
    if (!hsts) {
      vulnerabilities.push({
        type: 'security-header',
        severity: 'high',
        title: 'Missing Strict-Transport-Security Header',
        description: 'The Strict-Transport-Security (HSTS) header is missing. This header forces browsers to use HTTPS and prevents protocol downgrade attacks.',
        location: target,
        evidence: 'Header: Strict-Transport-Security is missing\nRecommendation: Add "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"',
      });
      if (verbose) console.log('   [MISSING] Strict-Transport-Security');
    } else {
      // Vérifier si max-age est suffisant (au moins 6 mois = 15768000 secondes)
      const maxAgeMatch = hsts.match(/max-age=(\d+)/);
      if (maxAgeMatch) {
        const maxAge = parseInt(maxAgeMatch[1]);
        if (maxAge < 15768000) { // Moins de 6 mois
          vulnerabilities.push({
            type: 'security-header',
            severity: 'medium',
            title: 'Weak HSTS Configuration',
            description: `The HSTS max-age is set to ${maxAge} seconds, which is less than the recommended 6 months (15768000 seconds).`,
            location: target,
            evidence: `Current value: ${hsts}\nRecommendation: Increase max-age to at least 31536000 (1 year)`,
          });
          if (verbose) console.log(`   [WEAK] HSTS max-age too low: ${maxAge}s`);
        } else if (verbose) {
          console.log(`   [OK] Present: Strict-Transport-Security = ${hsts}`);
        }
      } else if (verbose) {
        console.log(`   [OK] Present: Strict-Transport-Security = ${hsts}`);
      }
    }

    // Vérifier X-Content-Type-Options
    const xContentType = headers['x-content-type-options'];
    if (!xContentType || xContentType.toLowerCase() !== 'nosniff') {
      vulnerabilities.push({
        type: 'security-header',
        severity: 'medium',
        title: 'Missing X-Content-Type-Options Header',
        description: 'The X-Content-Type-Options header is missing or not set to "nosniff". This allows browsers to MIME-sniff responses, potentially leading to security issues.',
        location: target,
        evidence: `Current value: ${xContentType || 'missing'}\nRecommendation: Add "X-Content-Type-Options: nosniff"`,
      });
      if (verbose) console.log('   [MISSING] X-Content-Type-Options');
    } else if (verbose) {
      console.log(`   [OK] Present: X-Content-Type-Options = ${xContentType}`);
    }

    // Vérifier X-XSS-Protection
    const xssProtection = headers['x-xss-protection'];
    if (!xssProtection) {
      vulnerabilities.push({
        type: 'security-header',
        severity: 'low',
        title: 'Missing X-XSS-Protection Header',
        description: 'The X-XSS-Protection header is missing. While deprecated in modern browsers, it still provides protection for legacy browsers.',
        location: target,
        evidence: 'Header: X-XSS-Protection is missing\nRecommendation: Add "X-XSS-Protection: 1; mode=block"',
      });
      if (verbose) console.log('   [MISSING] X-XSS-Protection');
    } else if (verbose) {
      console.log(`   [OK] Present: X-XSS-Protection = ${xssProtection}`);
    }

    // Vérifier Referrer-Policy
    const referrerPolicy = headers['referrer-policy'];
    if (!referrerPolicy) {
      vulnerabilities.push({
        type: 'security-header',
        severity: 'low',
        title: 'Missing Referrer-Policy Header',
        description: 'The Referrer-Policy header is missing. This may leak sensitive information through the Referer header.',
        location: target,
        evidence: 'Header: Referrer-Policy is missing\nRecommendation: Add "Referrer-Policy: no-referrer" or "strict-origin-when-cross-origin"',
      });
      if (verbose) console.log('   [MISSING] Referrer-Policy');
    } else if (['unsafe-url', 'no-referrer-when-downgrade'].includes(referrerPolicy.toLowerCase())) {
      vulnerabilities.push({
        type: 'security-header',
        severity: 'low',
        title: 'Weak Referrer-Policy Configuration',
        description: `The Referrer-Policy is set to "${referrerPolicy}" which may leak sensitive information in URLs.`,
        location: target,
        evidence: `Current value: ${referrerPolicy}\nRecommendation: Use "no-referrer" or "strict-origin-when-cross-origin"`,
      });
      if (verbose) console.log(`   [WEAK] Referrer-Policy = ${referrerPolicy}`);
    } else if (verbose) {
      console.log(`   [OK] Present: Referrer-Policy = ${referrerPolicy}`);
    }

    // Vérifier Permissions-Policy
    const permissionsPolicy = headers['permissions-policy'];
    const featurePolicy = headers['feature-policy'];
    if (!permissionsPolicy && !featurePolicy) {
      vulnerabilities.push({
        type: 'security-header',
        severity: 'low',
        title: 'Missing Permissions-Policy Header',
        description: 'The Permissions-Policy header is missing. This header controls which browser features and APIs can be used.',
        location: target,
        evidence: 'Header: Permissions-Policy is missing\nRecommendation: Add Permissions-Policy to restrict unnecessary features (camera, microphone, geolocation, etc.)',
      });
      if (verbose) console.log('   [MISSING] Permissions-Policy');
    } else if (verbose) {
      console.log(`   [OK] Present: Permissions-Policy or Feature-Policy`);
    }

    // === VÉRIFICATIONS SUPPLÉMENTAIRES ===

    // Vérifier HTTPS
    if (!target.startsWith('https://')) {
      vulnerabilities.push({
        type: 'security-header',
        severity: 'high',
        title: 'Insecure HTTP Connection',
        description: 'The application is accessed over HTTP instead of HTTPS. This exposes all traffic to potential interception and manipulation.',
        location: target,
        evidence: 'URL scheme: http:// (should be https://)',
      });
      if (verbose) console.log('   [CRITICAL] Site not using HTTPS!');
    }

    // Vérifier les cookies (nécessite une requête GET pour récupérer les cookies)
    // On fait une requête GET uniquement si on veut vérifier les cookies
    try {
      const cookieResponse = await axios.get(target, {
        timeout: 5000,
        headers: { 'User-Agent': 'VulnScanner/2.0' },
        maxRedirects: 5,
        validateStatus: () => true,
      });

      const cookies = cookieResponse.headers['set-cookie'];
      if (cookies) {
        for (const cookie of cookies) {
          if (!cookie.includes('Secure')) {
            vulnerabilities.push({
              type: 'security-header',
              severity: 'medium',
              title: 'Cookie Missing Secure Flag',
              description: 'Session cookies do not have the Secure flag set, allowing them to be transmitted over insecure HTTP connections.',
              location: target,
              evidence: `Cookie: ${cookie.substring(0, 50)}...`,
            });
            if (verbose) console.log('   [WARNING] Cookie without Secure flag detected');
          }

          if (!cookie.includes('HttpOnly')) {
            vulnerabilities.push({
              type: 'security-header',
              severity: 'medium',
              title: 'Cookie Missing HttpOnly Flag',
              description: 'Session cookies do not have the HttpOnly flag set, making them accessible to JavaScript and vulnerable to XSS attacks.',
              location: target,
              evidence: `Cookie: ${cookie.substring(0, 50)}...`,
            });
            if (verbose) console.log('   [WARNING] Cookie without HttpOnly flag detected');
          }
        }
      }
    } catch (cookieError) {
      // Si la requête GET échoue, ce n'est pas grave, on continue sans vérifier les cookies
      if (verbose) console.log('   [INFO] Could not verify cookies');
    }

    if (verbose) {
      console.log(`\n   [SUMMARY] Security Headers scan completed: ${vulnerabilities.length} issues found\n`);
    }

  } catch (error) {
    console.error('Error scanning security headers:', error);
    // En cas d'erreur, on n'ajoute pas de vulnérabilité
  }

  return vulnerabilities;
}
