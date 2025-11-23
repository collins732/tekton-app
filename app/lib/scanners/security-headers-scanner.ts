import axios from 'axios';
import { Vulnerability } from '../types';

/**
 * SECURITY HEADERS SCANNER
 *
 * Ce scanner trouve TOUJOURS des problèmes car presque aucun site
 * n'a TOUS les headers de sécurité recommandés.
 *
 * PARFAIT pour les présentations bancaires !
 */

interface SecurityHeader {
  name: string;
  description: string;
  recommended: string;
  severity: 'high' | 'medium' | 'low';
}

const SECURITY_HEADERS: SecurityHeader[] = [
  {
    name: 'Strict-Transport-Security',
    description: 'Force HTTPS connections',
    recommended: 'max-age=31536000; includeSubDomains',
    severity: 'high',
  },
  {
    name: 'X-Frame-Options',
    description: 'Prevent clickjacking attacks',
    recommended: 'DENY or SAMEORIGIN',
    severity: 'high',
  },
  {
    name: 'X-Content-Type-Options',
    description: 'Prevent MIME type sniffing',
    recommended: 'nosniff',
    severity: 'medium',
  },
  {
    name: 'Content-Security-Policy',
    description: 'Prevent XSS and data injection',
    recommended: "default-src 'self'",
    severity: 'high',
  },
  {
    name: 'X-XSS-Protection',
    description: 'Enable browser XSS filter',
    recommended: '1; mode=block',
    severity: 'medium',
  },
  {
    name: 'Referrer-Policy',
    description: 'Control referrer information',
    recommended: 'no-referrer or strict-origin-when-cross-origin',
    severity: 'low',
  },
  {
    name: 'Permissions-Policy',
    description: 'Control browser features',
    recommended: 'geolocation=(), microphone=(), camera=()',
    severity: 'medium',
  },
];

export async function scanSecurityHeaders(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];

  console.log('\n[Security Headers] Starting scan...');

  try {
    const response = await axios.get(target, {
      timeout: 10000,
      validateStatus: () => true,
      headers: { 'User-Agent': 'VulnScanner/2.0' },
    });

    console.log(`   [OK] Target responded with status ${response.status}`);
    console.log('   [INFO] Checking security headers...');

    let missingCount = 0;
    let weakCount = 0;

    for (const header of SECURITY_HEADERS) {
      const headerValue = response.headers[header.name.toLowerCase()];

      if (!headerValue) {
        // Header complètement manquant
        vulnerabilities.push({
          type: 'config',
          severity: header.severity,
          title: `Missing Security Header: ${header.name}`,
          description: `The HTTP response does not include the "${header.name}" security header. ${header.description}. This leaves the application vulnerable to various attacks.`,
          location: target,
          evidence: `Header "${header.name}" is missing\nRecommended: ${header.recommended}`,
        });

        console.log(`   [MISSING] ${header.name}`);
        missingCount++;
      } else {
        // Header présent mais vérifier s'il est faible
        console.log(`   [OK] Present: ${header.name} = ${headerValue}`);

        // Vérifications supplémentaires pour certains headers
        if (header.name === 'Strict-Transport-Security' && !headerValue.includes('max-age')) {
          vulnerabilities.push({
            type: 'config',
            severity: 'medium',
            title: `Weak Security Header: ${header.name}`,
            description: `The HSTS header is present but does not specify a max-age directive, reducing its effectiveness.`,
            location: target,
            evidence: `Current value: ${headerValue}\nRecommended: ${header.recommended}`,
          });
          weakCount++;
        }

        if (header.name === 'Content-Security-Policy' && headerValue.includes('unsafe-inline')) {
          vulnerabilities.push({
            type: 'config',
            severity: 'medium',
            title: `Weak Content Security Policy`,
            description: `The CSP header allows 'unsafe-inline', which reduces protection against XSS attacks.`,
            location: target,
            evidence: `Current value: ${headerValue}\nSuggestion: Remove 'unsafe-inline' directive`,
          });
          weakCount++;
        }
      }
    }

    // Vérifier HTTPS
    if (!target.startsWith('https://')) {
      vulnerabilities.push({
        type: 'config',
        severity: 'high',
        title: 'Insecure HTTP Connection',
        description: 'The application is accessed over HTTP instead of HTTPS. This exposes all traffic to potential interception and manipulation.',
        location: target,
        evidence: 'URL scheme: http:// (should be https://)',
      });
      console.log('   [CRITICAL] Site not using HTTPS!');
    }

    // Vérifier les cookies
    const cookies = response.headers['set-cookie'];
    if (cookies) {
      for (const cookie of cookies) {
        if (!cookie.includes('Secure')) {
          vulnerabilities.push({
            type: 'config',
            severity: 'medium',
            title: 'Cookie Missing Secure Flag',
            description: 'Session cookies do not have the Secure flag set, allowing them to be transmitted over insecure HTTP connections.',
            location: target,
            evidence: `Cookie: ${cookie.substring(0, 50)}...`,
          });
          console.log('   [WARNING] Cookie without Secure flag detected');
        }

        if (!cookie.includes('HttpOnly')) {
          vulnerabilities.push({
            type: 'config',
            severity: 'medium',
            title: 'Cookie Missing HttpOnly Flag',
            description: 'Session cookies do not have the HttpOnly flag set, making them accessible to JavaScript and vulnerable to XSS attacks.',
            location: target,
            evidence: `Cookie: ${cookie.substring(0, 50)}...`,
          });
          console.log('   [WARNING] Cookie without HttpOnly flag detected');
        }
      }
    }

    console.log(`\n   [SUMMARY]`);
    console.log(`      Missing headers: ${missingCount}`);
    console.log(`      Weak headers: ${weakCount}`);
    console.log(`      Total issues: ${vulnerabilities.length}`);

  } catch (error) {
    console.error('   [ERROR] Error scanning security headers:', error);
  }

  console.log(`\n   [COMPLETED] Security Headers scan completed: ${vulnerabilities.length} issues found\n`);
  return vulnerabilities;
}
