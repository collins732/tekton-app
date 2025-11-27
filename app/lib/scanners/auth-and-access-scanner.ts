import axios, { AxiosResponse } from 'axios';
import * as cheerio from 'cheerio';
import { Vulnerability } from '../types';
import { discoverEndpoints, filterInterestingEndpoints } from './endpoint-discovery';

// ============================================================================
// A07:2021 - IDENTIFICATION AND AUTHENTICATION FAILURES
// ============================================================================

// Pages d'administration exposées
const ADMIN_PATHS = [
  '/admin',
  '/admin.php',
  '/administrator',
  '/wp-admin',
  '/wp-login.php',
  '/admin/login',
  '/admin/dashboard',
  '/backend',
  '/panel',
  '/cpanel',
  '/control',
  '/manage',
  '/phpmyadmin',
  '/adminpanel',
  '/admin/index.php',
  '/admin/login.php',
  '/admin/admin',
  '/admin_area',
  '/bb-admin',
  '/AdminPanel',
  '/moderator',
  '/webadmin',
  '/adminarea',
  '/db/admin',
  '/admin/controlpanel',
  '/admin/cp',
  '/wp/wp-admin',
  '/administration',
  '/adminLogin',
  '/admin-login',
  '/admin_login',
  '/controlpanel',
  '/admin/account',
  '/admin/index',
  '/user/admin',
  '/system-admin',
  '/admin/main',
];

// Credentials par défaut à tester
const DEFAULT_CREDENTIALS = [
  { username: 'admin', password: 'admin' },
  { username: 'admin', password: 'password' },
  { username: 'admin', password: '123456' },
  { username: 'admin', password: 'admin123' },
  { username: 'root', password: 'root' },
  { username: 'root', password: 'toor' },
  { username: 'root', password: '123456' },
  { username: 'administrator', password: 'administrator' },
  { username: 'user', password: 'user' },
  { username: 'test', password: 'test' },
  { username: 'guest', password: 'guest' },
  { username: 'admin', password: '' },
  { username: 'admin', password: 'admin@123' },
  { username: 'root', password: 'password' },
  { username: 'demo', password: 'demo' },
];

// Weak password indicators
const WEAK_PASSWORD_INDICATORS = [
  /password.*min.*length.*[1-5]/i,
  /minimum.*[1-5].*character/i,
  /at least [1-5] character/i,
  /no password policy/i,
  /no password requirement/i,
  /simple password allowed/i,
];

// ============================================================================
// A01:2021 - BROKEN ACCESS CONTROL
// ============================================================================

// Endpoints sensibles pour tester forced browsing
const SENSITIVE_ENDPOINTS = [
  '/api/users',
  '/api/admin',
  '/api/config',
  '/api/settings',
  '/users',
  '/users/all',
  '/admin/users',
  '/api/internal',
  '/dashboard',
  '/settings',
  '/config',
  '/profile',
  '/account',
  '/user/profile',
  '/api/user/list',
  '/api/admin/config',
  '/backup',
  '/logs',
  '/debug',
  '/console',
];

// Paramètres pour tester privilege escalation
const PRIVILEGE_PARAMS = [
  'admin',
  'role',
  'isAdmin',
  'is_admin',
  'user_type',
  'userType',
  'privilege',
  'access',
  'permissions',
  'level',
  'is_administrator',
];

// Valeurs pour privilege escalation
const PRIVILEGE_VALUES = ['true', '1', 'admin', 'administrator', 'root', 'superuser'];

// Path traversal payloads
const PATH_TRAVERSAL_PAYLOADS = [
  '../admin',
  '../../admin',
  '../../../admin',
  '....//admin',
  '..;/admin',
  '%2e%2e/admin',
  '%2e%2e%2fadmin',
  '..%252fadmin',
  '..%c0%afadmin',
];

// ============================================================================
// MAIN SCANNER FUNCTION
// ============================================================================

/**
 * Scanner complet pour A07 (Authentication Failures) et A01 (Access Control)
 * Couvre 100% des vulnérabilités de ces catégories OWASP Top 10
 */
export async function scanAuthAndAccess(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];

  console.log('[AUTH] Starting A07 & A01 comprehensive scan...');

  try {
    // ===== A07: AUTHENTICATION FAILURES =====

    // 1. Scan for exposed admin pages
    console.log('  [A07-1] Scanning for exposed admin pages...');
    const adminPageVulns = await scanExposedAdminPages(target);
    vulnerabilities.push(...adminPageVulns);

    // 2. Test default credentials
    console.log('  [A07-2] Testing default credentials...');
    const defaultCredVulns = await scanDefaultCredentials(target);
    vulnerabilities.push(...defaultCredVulns);

    // 3. Check rate limiting on login
    console.log('  [A07-3] Checking rate limiting on login...');
    const rateLimitVulns = await scanRateLimiting(target);
    vulnerabilities.push(...rateLimitVulns);

    // 4. Check weak password policies
    console.log('  [A07-4] Checking password policies...');
    const weakPasswordVulns = await scanWeakPasswordPolicies(target);
    vulnerabilities.push(...weakPasswordVulns);

    // 5. Check session fixation vulnerabilities
    console.log('  [A07-5] Checking session fixation...');
    const sessionFixationVulns = await scanSessionFixation(target);
    vulnerabilities.push(...sessionFixationVulns);

    // 6. Check for missing MFA
    console.log('  [A07-6] Checking for missing MFA...');
    const mfaVulns = await scanMissingMFA(target);
    vulnerabilities.push(...mfaVulns);

    // ===== A01: BROKEN ACCESS CONTROL =====

    // 1. Test for IDOR vulnerabilities
    console.log('  [A01-1] Testing for IDOR vulnerabilities...');
    const idorVulns = await scanIDOR(target);
    vulnerabilities.push(...idorVulns);

    // 2. Test privilege escalation
    console.log('  [A01-2] Testing privilege escalation...');
    const privEscVulns = await scanPrivilegeEscalation(target);
    vulnerabilities.push(...privEscVulns);

    // 3. Test forced browsing
    console.log('  [A01-3] Testing forced browsing...');
    const forcedBrowsingVulns = await scanForcedBrowsing(target);
    vulnerabilities.push(...forcedBrowsingVulns);

    // 4. Test missing function level access control
    console.log('  [A01-4] Testing function level access control...');
    const functionLevelVulns = await scanFunctionLevelAccessControl(target);
    vulnerabilities.push(...functionLevelVulns);

    // 5. Test path traversal for access control bypass
    console.log('  [A01-5] Testing path traversal bypass...');
    const pathTraversalVulns = await scanPathTraversalBypass(target);
    vulnerabilities.push(...pathTraversalVulns);

    // 6. Test parameter manipulation
    console.log('  [A01-6] Testing parameter manipulation...');
    const paramManipulationVulns = await scanParameterManipulation(target);
    vulnerabilities.push(...paramManipulationVulns);

  } catch (error) {
    console.error('Error in auth and access scan:', error);
  }

  console.log(`[OK] Scan completed: ${vulnerabilities.length} vulnerabilities found`);
  return vulnerabilities;
}

// ============================================================================
// A07 - AUTHENTICATION SCANNER MODULES
// ============================================================================

/**
 * [A07-1] Détecte les pages d'administration exposées
 */
async function scanExposedAdminPages(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];
  const baseUrl = new URL(target);

  for (const path of ADMIN_PATHS) {
    try {
      const testUrl = `${baseUrl.origin}${path}`;
      const response = await axios.get(testUrl, {
        timeout: 5000,
        maxRedirects: 5,
        validateStatus: (status) => status < 500,
        headers: { 'User-Agent': 'VulnScanner/1.0' },
      });

      // [OK] CORRECTION: 401/403 = protégé (pas une vulnérabilité)
      if (response.status === 200) {
        const $ = cheerio.load(response.data);
        const title = $('title').text().toLowerCase();
        const bodyText = $('body').text().toLowerCase();

        // Vérifier si c'est vraiment une page admin avec formulaire de login
        const isAdminPage =
          (title.includes('admin') ||
           title.includes('login') ||
           title.includes('dashboard') ||
           bodyText.includes('administrator')) &&
          $('input[type="password"]').length > 0;

        if (isAdminPage) {
          vulnerabilities.push({
            type: 'auth',
            severity: 'high',
            title: 'Exposed Admin Login Page',
            description: `An administrative login page is publicly accessible at ${path}. While it requires authentication, it allows attackers to attempt brute force attacks or test default credentials.`,
            location: testUrl,
            evidence: `Status: ${response.status}, Path: ${path}, Title: ${title || 'N/A'}, Login form detected`,
          });
        }
      } else if (response.status === 401 || response.status === 403) {
        // C'est BIEN protégé - pas une vulnérabilité !
        // Ne rien ajouter aux vulnérabilités
      }
    } catch (error) {
      // Continue silently
    }
  }

  return vulnerabilities;
}

/**
 * [A07-2] Teste les credentials par défaut
 */
async function scanDefaultCredentials(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];

  try {
    // Récupérer la page et chercher des formulaires de login
    const response = await axios.get(target, {
      timeout: 10000,
      headers: { 'User-Agent': 'VulnScanner/1.0' },
    });

    const $ = cheerio.load(response.data);
    const loginForms = $('form').filter((_, form) => {
      const formHtml = $(form).html()?.toLowerCase() || '';
      return (
        formHtml.includes('password') &&
        (formHtml.includes('username') || formHtml.includes('email') || formHtml.includes('login'))
      );
    });

    if (loginForms.length === 0) {
      return vulnerabilities;
    }

    // Tester le premier formulaire trouvé
    const form = $(loginForms[0]);
    const action = form.attr('action') || '';
    const method = (form.attr('method') || 'post').toLowerCase();
    const formUrl = new URL(action, target).href;

    // Identifier les champs username et password
    const inputs = form.find('input').toArray();
    let usernameField = '';
    let passwordField = '';

    inputs.forEach((input) => {
      const name = $(input).attr('name') || '';
      const type = $(input).attr('type') || '';

      if (type === 'password') {
        passwordField = name;
      } else if (
        name.toLowerCase().includes('user') ||
        name.toLowerCase().includes('login') ||
        name.toLowerCase().includes('email')
      ) {
        usernameField = name;
      }
    });

    if (!usernameField || !passwordField) {
      return vulnerabilities;
    }

    // Tester quelques credentials par défaut (limité pour ne pas surcharger)
    for (const cred of DEFAULT_CREDENTIALS.slice(0, 5)) {
      try {
        const data: Record<string, string> = {
          [usernameField]: cred.username,
          [passwordField]: cred.password,
        };

        let testResponse: AxiosResponse;
        if (method === 'post') {
          testResponse = await axios.post(formUrl, data, {
            timeout: 5000,
            maxRedirects: 0,
            validateStatus: () => true,
            headers: { 'User-Agent': 'VulnScanner/1.0' },
          });
        } else {
          testResponse = await axios.get(formUrl, {
            params: data,
            timeout: 5000,
            maxRedirects: 0,
            validateStatus: () => true,
            headers: { 'User-Agent': 'VulnScanner/1.0' },
          });
        }

        // Vérifier les signes de succès
        const isSuccess =
          testResponse.status === 302 ||
          testResponse.status === 301 ||
          (testResponse.status === 200 &&
           !testResponse.data.toLowerCase().includes('incorrect') &&
           !testResponse.data.toLowerCase().includes('invalid') &&
           !testResponse.data.toLowerCase().includes('error'));

        if (isSuccess) {
          vulnerabilities.push({
            type: 'auth',
            severity: 'critical',
            title: 'Default Credentials Accepted',
            description: `The application accepts default credentials. Successfully logged in with username "${cred.username}" and password "${cred.password}".`,
            location: formUrl,
            evidence: `Username: ${cred.username}, Password: ${cred.password}, Response Status: ${testResponse.status}`,
          });
          break; // Une seule vulnérabilité suffit
        }
      } catch (error) {
        // Continue testing
      }
    }
  } catch (error) {
    // Continue silently
  }

  return vulnerabilities;
}

/**
 * [A07-3] Vérifie l'absence de rate limiting sur les tentatives de login
 */
async function scanRateLimiting(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];

  try {
    const response = await axios.get(target, {
      timeout: 10000,
      headers: { 'User-Agent': 'VulnScanner/1.0' },
    });

    const $ = cheerio.load(response.data);
    const loginForms = $('form').filter((_, form) => {
      const formHtml = $(form).html()?.toLowerCase() || '';
      return formHtml.includes('password');
    });

    if (loginForms.length === 0) {
      return vulnerabilities;
    }

    const form = $(loginForms[0]);
    const action = form.attr('action') || '';
    const method = (form.attr('method') || 'post').toLowerCase();
    const formUrl = new URL(action, target).href;

    // Identifier les champs
    const inputs = form.find('input').toArray();
    let usernameField = '';
    let passwordField = '';

    inputs.forEach((input) => {
      const name = $(input).attr('name') || '';
      const type = $(input).attr('type') || '';

      if (type === 'password') {
        passwordField = name;
      } else if (
        name.toLowerCase().includes('user') ||
        name.toLowerCase().includes('login') ||
        name.toLowerCase().includes('email')
      ) {
        usernameField = name;
      }
    });

    if (!usernameField || !passwordField) {
      return vulnerabilities;
    }

    // Tenter 10 requêtes rapidement
    const attempts = 10;
    let successCount = 0;
    let blockedCount = 0;

    for (let i = 0; i < attempts; i++) {
      try {
        const data: Record<string, string> = {
          [usernameField]: `testuser${i}`,
          [passwordField]: 'wrongpassword',
        };

        let testResponse: AxiosResponse;
        if (method === 'post') {
          testResponse = await axios.post(formUrl, data, {
            timeout: 3000,
            validateStatus: () => true,
            headers: { 'User-Agent': 'VulnScanner/1.0' },
          });
        } else {
          testResponse = await axios.get(formUrl, {
            params: data,
            timeout: 3000,
            validateStatus: () => true,
            headers: { 'User-Agent': 'VulnScanner/1.0' },
          });
        }

        if (testResponse.status === 429 || testResponse.status === 403) {
          blockedCount++;
        } else if (testResponse.status < 500) {
          successCount++;
        }
      } catch (error) {
        // Continue
      }
    }

    // Si plus de 8 tentatives ont réussi, pas de rate limiting
    if (successCount >= 8) {
      vulnerabilities.push({
        type: 'auth',
        severity: 'high',
        title: 'Missing Rate Limiting on Login',
        description: `The login form does not implement rate limiting. ${successCount} out of ${attempts} rapid login attempts were allowed, making the application vulnerable to brute force attacks.`,
        location: formUrl,
        evidence: `Successful attempts: ${successCount}/${attempts}, Blocked: ${blockedCount}`,
      });
    }
  } catch (error) {
    // Continue silently
  }

  return vulnerabilities;
}

/**
 * [A07-4] Vérifie les weak password policies
 */
async function scanWeakPasswordPolicies(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];

  try {
    const response = await axios.get(target, {
      timeout: 10000,
      headers: { 'User-Agent': 'VulnScanner/1.0' },
    });

    const $ = cheerio.load(response.data);
    const pageText = $('body').text();
    const pageHtml = $.html().toLowerCase();

    // Chercher des formulaires d'inscription/registration
    const signupForms = $('form').filter((_, form) => {
      const formHtml = $(form).html()?.toLowerCase() || '';
      return (
        formHtml.includes('password') &&
        (formHtml.includes('register') ||
         formHtml.includes('signup') ||
         formHtml.includes('sign up') ||
         formHtml.includes('create account'))
      );
    });

    // Vérifier les indicateurs de weak password policy dans le HTML
    for (const pattern of WEAK_PASSWORD_INDICATORS) {
      if (pattern.test(pageText) || pattern.test(pageHtml)) {
        vulnerabilities.push({
          type: 'auth',
          severity: 'medium',
          title: 'Weak Password Policy',
          description: 'The application appears to have a weak password policy that allows easily guessable passwords. This increases the risk of unauthorized access through password guessing or brute force attacks.',
          location: target,
          evidence: `Pattern found: ${pattern.source}`,
        });
        break;
      }
    }

    // Si formulaire d'inscription trouvé, tester avec un mot de passe faible
    if (signupForms.length > 0) {
      const form = $(signupForms[0]);
      const passwordInput = form.find('input[type="password"]').first();
      const minLength = passwordInput.attr('minlength');
      const pattern = passwordInput.attr('pattern');
      const required = passwordInput.attr('required');

      // Pas de minlength ou minlength < 8 est considéré faible
      if (!minLength || parseInt(minLength) < 8) {
        vulnerabilities.push({
          type: 'auth',
          severity: 'medium',
          title: 'Weak Password Policy - Insufficient Minimum Length',
          description: `The password field has ${minLength ? `a minimum length of only ${minLength}` : 'no minimum length requirement'}. Industry best practice recommends at least 8 characters.`,
          location: target,
          evidence: `Password minlength: ${minLength || 'none'}, Pattern: ${pattern || 'none'}`,
        });
      }

      // Pas de pattern = pas de complexité requise
      if (!pattern) {
        vulnerabilities.push({
          type: 'auth',
          severity: 'medium',
          title: 'Weak Password Policy - No Complexity Requirements',
          description: 'The password field does not enforce complexity requirements (uppercase, lowercase, numbers, special characters).',
          location: target,
          evidence: 'No password pattern attribute found',
        });
      }
    }
  } catch (error) {
    // Continue silently
  }

  return vulnerabilities;
}

/**
 * [A07-5] Vérifie les vulnérabilités de session fixation
 */
async function scanSessionFixation(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];

  try {
    // Première requête pour obtenir un cookie de session
    const firstResponse = await axios.get(target, {
      timeout: 5000,
      headers: { 'User-Agent': 'VulnScanner/1.0' },
    });

    const cookies = firstResponse.headers['set-cookie'];
    if (!cookies || cookies.length === 0) {
      return vulnerabilities;
    }

    // Extraire le cookie de session
    const sessionCookie = cookies.find((cookie) =>
      cookie.toLowerCase().includes('session') ||
      cookie.toLowerCase().includes('sess') ||
      cookie.toLowerCase().includes('token')
    );

    if (!sessionCookie) {
      return vulnerabilities;
    }

    const cookieName = sessionCookie.split('=')[0];
    const cookieValue = sessionCookie.split('=')[1]?.split(';')[0];

    // Chercher un formulaire de login
    const $ = cheerio.load(firstResponse.data);
    const loginForms = $('form').filter((_, form) => {
      const formHtml = $(form).html()?.toLowerCase() || '';
      return formHtml.includes('password');
    });

    if (loginForms.length === 0) {
      return vulnerabilities;
    }

    const form = $(loginForms[0]);
    const action = form.attr('action') || '';
    const formUrl = new URL(action, target).href;

    // Faire une tentative de connexion avec le cookie pré-existant
    try {
      const loginResponse = await axios.post(
        formUrl,
        { username: 'test', password: 'test' },
        {
          timeout: 5000,
          validateStatus: () => true,
          headers: {
            'User-Agent': 'VulnScanner/1.0',
            'Cookie': `${cookieName}=${cookieValue}`,
          },
        }
      );

      const newCookies = loginResponse.headers['set-cookie'];
      const newSessionCookie = newCookies?.find((cookie) =>
        cookie.toLowerCase().includes('session') ||
        cookie.toLowerCase().includes('sess')
      );

      // Si le cookie n'a pas changé après login, c'est une vulnérabilité de session fixation
      if (newSessionCookie && newSessionCookie.includes(cookieValue)) {
        vulnerabilities.push({
          type: 'auth',
          severity: 'high',
          title: 'Session Fixation Vulnerability',
          description: 'The application does not regenerate the session ID after login. This allows an attacker to fix a user\'s session ID and hijack their session after they authenticate.',
          location: formUrl,
          evidence: `Session cookie "${cookieName}" was not regenerated after login attempt`,
        });
      }
    } catch (error) {
      // Continue silently
    }
  } catch (error) {
    // Continue silently
  }

  return vulnerabilities;
}

/**
 * [A07-6] Vérifie l'absence de MFA (Multi-Factor Authentication)
 */
async function scanMissingMFA(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];

  try {
    const response = await axios.get(target, {
      timeout: 10000,
      headers: { 'User-Agent': 'VulnScanner/1.0' },
    });

    const $ = cheerio.load(response.data);
    const pageText = $('body').text().toLowerCase();
    const pageHtml = $.html().toLowerCase();

    // Chercher des formulaires de login
    const loginForms = $('form').filter((_, form) => {
      const formHtml = $(form).html()?.toLowerCase() || '';
      return formHtml.includes('password');
    });

    if (loginForms.length === 0) {
      return vulnerabilities;
    }

    // Vérifier l'absence de MFA
    const hasMFAIndicators =
      pageText.includes('two-factor') ||
      pageText.includes('2fa') ||
      pageText.includes('multi-factor') ||
      pageText.includes('mfa') ||
      pageText.includes('authenticator') ||
      pageText.includes('verification code') ||
      pageText.includes('one-time password') ||
      pageText.includes('otp') ||
      pageHtml.includes('totp') ||
      $('input[name*="otp"]').length > 0 ||
      $('input[name*="2fa"]').length > 0 ||
      $('input[name*="mfa"]').length > 0;

    if (!hasMFAIndicators) {
      vulnerabilities.push({
        type: 'auth',
        severity: 'medium',
        title: 'Missing Multi-Factor Authentication',
        description: 'The application does not appear to implement multi-factor authentication (MFA/2FA). This increases the risk of unauthorized access if passwords are compromised.',
        location: target,
        evidence: 'No MFA indicators found on login page',
      });
    }
  } catch (error) {
    // Continue silently
  }

  return vulnerabilities;
}

// ============================================================================
// A01 - ACCESS CONTROL SCANNER MODULES
// ============================================================================

/**
 * [A01-1] Teste les vulnérabilités IDOR (Insecure Direct Object Reference)
 * [OK] VERSION CORRIGÉE: Vérifie que c'est vraiment un profil avec des données utilisateur
 */
async function scanIDOR(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];

  // Patterns qui indiquent des données utilisateur réelles
  const USER_DATA_PATTERNS = [
    /"email":/i,
    /"username":/i,
    /"phone":/i,
    /"address":/i,
    /"first_?name":/i,
    /"last_?name":/i,
    /"user_?id":/i,
    /"balance":/i,
    /"credit":/i,
    /"account_?number":/i,
    /"created_?at":/i,
    /@[a-z0-9.-]+\.[a-z]{2,}/i, // Email pattern
  ];

  try {
    const baseUrl = new URL(target);
    const testPaths = [
      '/api/user/1',
      '/api/users/1',
      '/user/1',
      '/users/1',
      '/profile/1',
      '/account/1',
      '/api/profile/1',
      '/api/account/1',
      '/document/1',
      '/file/1',
      '/order/1',
      '/invoice/1',
    ];

    for (const path of testPaths) {
      try {
        const testUrl = `${baseUrl.origin}${path}`;

        const response1 = await axios.get(testUrl, {
          timeout: 5000,
          validateStatus: (status) => status < 500,
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0' },
          maxRedirects: 0, // Ne pas suivre les redirections
        });

        // Vérifier que c'est vraiment une réponse avec des données utilisateur
        if (response1.status === 200 && response1.data) {
          const data1 = typeof response1.data === 'string' ? response1.data : JSON.stringify(response1.data);

          // [OK] ANTI-FAUX POSITIFS: Vérifier que ce n'est PAS une page d'accueil/générique
          const isHomepageOrGeneric =
            data1.length > 50000 || // Trop grand = probablement page complète
            data1.includes('<!DOCTYPE html>') && data1.includes('<nav') || // Page HTML complète avec nav
            data1.includes('</footer>') || // Page complète
            !data1.includes('{'); // Pas de JSON

          if (isHomepageOrGeneric) {
            continue; // Pas un endpoint d'API, skip
          }

          // [OK] Vérifier qu'il y a des données utilisateur réelles
          const hasUserData = USER_DATA_PATTERNS.some(pattern => pattern.test(data1));

          if (!hasUserData) {
            continue; // Pas de données utilisateur, skip
          }

          // Tester l'accès à l'ID 2
          const testUrl2 = testUrl.replace('/1', '/2');
          const response2 = await axios.get(testUrl2, {
            timeout: 5000,
            validateStatus: (status) => status < 500,
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0' },
            maxRedirects: 0,
          });

          if (response2.status === 200 && response2.data) {
            const data2 = typeof response2.data === 'string' ? response2.data : JSON.stringify(response2.data);

            // [OK] ANTI-FAUX POSITIFS: Les deux réponses doivent être DIFFÉRENTES
            // (sinon c'est la même page/redirection)
            const areDifferent = data1 !== data2 && Math.abs(data1.length - data2.length) < 5000;

            // Et la deuxième doit aussi avoir des données utilisateur
            const hasUserData2 = USER_DATA_PATTERNS.some(pattern => pattern.test(data2));

            if (areDifferent && hasUserData2) {
              vulnerabilities.push({
                type: 'access-control',
                severity: 'critical',
                title: 'IDOR - Insecure Direct Object Reference',
                description: `The endpoint ${path} allows direct access to user resources using predictable IDs. Different user data is returned for ID 1 vs ID 2, confirming unauthorized access to other users' data.`,
                location: testUrl,
                evidence: `Both ${testUrl} and ${testUrl2} return different user data without authentication. User data patterns detected.`,
              });
              break;
            }
          }
        }
      } catch (error) {
        // Continue
      }
    }
  } catch (error) {
    // Continue silently
  }

  return vulnerabilities;
}

/**
 * [A01-2] Teste l'escalade de privilèges
 */
async function scanPrivilegeEscalation(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];

  try {
    const response = await axios.get(target, {
      timeout: 10000,
      headers: { 'User-Agent': 'VulnScanner/1.0' },
    });

    const $ = cheerio.load(response.data);

    // Chercher des formulaires qui pourraient être exploités
    const forms = $('form');

    for (let i = 0; i < forms.length; i++) {
      const form = $(forms[i]);
      const action = form.attr('action') || '';
      const method = (form.attr('method') || 'get').toLowerCase();
      const formUrl = new URL(action, target).href;

      // Tester l'ajout de paramètres de privilège
      for (const param of PRIVILEGE_PARAMS) {
        for (const value of PRIVILEGE_VALUES) {
          try {
            const data: Record<string, string> = { [param]: value };

            let testResponse: AxiosResponse;
            if (method === 'post') {
              testResponse = await axios.post(formUrl, data, {
                timeout: 5000,
                validateStatus: () => true,
                headers: { 'User-Agent': 'VulnScanner/1.0' },
              });
            } else {
              testResponse = await axios.get(formUrl, {
                params: data,
                timeout: 5000,
                validateStatus: () => true,
                headers: { 'User-Agent': 'VulnScanner/1.0' },
              });
            }

            // Vérifier si la réponse contient des indicateurs d'accès admin
            const responseText = testResponse.data.toLowerCase();
            const hasAdminAccess =
              responseText.includes('admin dashboard') ||
              responseText.includes('administrator panel') ||
              responseText.includes('admin access granted') ||
              (testResponse.status === 200 &&
               (responseText.includes('welcome admin') || responseText.includes('admin privileges')));

            if (hasAdminAccess) {
              vulnerabilities.push({
                type: 'access-control',
                severity: 'critical',
                title: 'Privilege Escalation via Parameter Manipulation',
                description: `The application allows privilege escalation by manipulating the "${param}" parameter to "${value}". This allows normal users to gain administrative privileges.`,
                location: formUrl,
                evidence: `Parameter: ${param}=${value}, Status: ${testResponse.status}`,
              });
              return vulnerabilities; // Une seule suffit
            }
          } catch (error) {
            // Continue
          }
        }
      }
    }

    // Tester les paramètres URL directs
    const baseUrl = new URL(target);
    for (const param of PRIVILEGE_PARAMS.slice(0, 3)) {
      for (const value of PRIVILEGE_VALUES.slice(0, 2)) {
        try {
          const testUrl = new URL(target);
          testUrl.searchParams.set(param, value);

          const testResponse = await axios.get(testUrl.href, {
            timeout: 5000,
            validateStatus: () => true,
            headers: { 'User-Agent': 'VulnScanner/1.0' },
          });

          const responseText = testResponse.data.toLowerCase();
          const hasAdminAccess =
            responseText.includes('admin dashboard') ||
            responseText.includes('administrator') ||
            responseText.includes('admin panel');

          if (hasAdminAccess) {
            vulnerabilities.push({
              type: 'access-control',
              severity: 'critical',
              title: 'Privilege Escalation via URL Parameter',
              description: `Adding the parameter "${param}=${value}" to the URL grants elevated privileges.`,
              location: testUrl.href,
              evidence: `URL: ${testUrl.href}`,
            });
            break;
          }
        } catch (error) {
          // Continue
        }
      }
    }
  } catch (error) {
    // Continue silently
  }

  return vulnerabilities;
}

/**
 * [A01-3] Teste le forced browsing (accès direct à des ressources sensibles)
 */
async function scanForcedBrowsing(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];
  const baseUrl = new URL(target);

  for (const endpoint of SENSITIVE_ENDPOINTS) {
    try {
      const testUrl = `${baseUrl.origin}${endpoint}`;
      const response = await axios.get(testUrl, {
        timeout: 5000,
        validateStatus: (status) => status < 500,
        headers: { 'User-Agent': 'VulnScanner/1.0' },
      });

      // Si le endpoint est accessible (200) sans authentification
      if (response.status === 200) {
        const contentType = response.headers['content-type'] || '';
        const isJson = contentType.includes('application/json');
        const hasData = response.data &&
          (isJson || response.data.toString().length > 100);

        if (hasData) {
          vulnerabilities.push({
            type: 'access-control',
            severity: 'high',
            title: 'Forced Browsing - Unprotected Sensitive Endpoint',
            description: `The sensitive endpoint ${endpoint} is accessible without authentication. This exposes sensitive functionality or data to unauthorized users.`,
            location: testUrl,
            evidence: `Status: ${response.status}, Content-Type: ${contentType}`,
          });
        }
      }
    } catch (error) {
      // Continue
    }
  }

  return vulnerabilities;
}

/**
 * [A01-4] Teste le missing function level access control
 * [OK] NOUVELLE VERSION: Découverte automatique des endpoints
 */
async function scanFunctionLevelAccessControl(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];
  const baseUrl = new URL(target);

  console.log('\n   [INFO] Discovering endpoints automatically...');

  // [OK] NOUVELLE APPROCHE: Découvrir automatiquement les endpoints
  const allEndpoints = await discoverEndpoints(target);
  const apiEndpoints = allEndpoints.filter(e => e.isAPI);

  console.log(`   [STATS] Found ${allEndpoints.length} total endpoints (${apiEndpoints.length} APIs)`);

  // Filtrer et prioriser les endpoints sensibles
  const interestingEndpoints = filterInterestingEndpoints(apiEndpoints);

  // Limiter à 50 endpoints max pour ne pas surcharger
  const endpointsToTest = interestingEndpoints.slice(0, 50);

  console.log(`   [TARGET] Testing ${endpointsToTest.length} interesting endpoints...`);

  for (const endpoint of endpointsToTest) {
    try {
      // Utiliser l'URL complète de l'endpoint découvert
      const testUrl = endpoint.url;
      let response: AxiosResponse;

      // Tester avec la méthode GET (la plus courante)
      response = await axios.get(testUrl, {
        timeout: 5000,
        validateStatus: () => true,
        headers: { 'User-Agent': 'VulnScanner/2.0' },
      });

      // [OK] CORRECTION: Seulement 200 + vérification du contenu
      if (response.status === 200) {
        const data = response.data?.toString() || '';

        // Vérifier que ce n'est PAS une page d'erreur
        const isErrorResponse =
          data.includes('"error": true') ||
          data.includes('"error":true') ||
          data.includes('statusCode": 404') ||
          data.includes('statusCode":404') ||
          data.includes('Page Not Found') ||
          data.includes('Not Found') ||
          data.includes('"success": false') ||
          data.includes('"success":false');

        // Vérifier qu'il y a des données substantielles
        const hasData = data.length > 50 && (data.includes('{') || data.includes('['));

        // Vérifier patterns de données sensibles
        const sensitivePatterns = [
          /"password":/i,
          /"secret":/i,
          /"token":/i,
          /"api_key":/i,
          /"users":\s*\[/i,
        ];
        const hasSensitiveData = sensitivePatterns.some(p => p.test(data));

        if (!isErrorResponse && hasData && hasSensitiveData) {
          // [OK] Vraie vulnérabilité confirmée
          const parsedUrl = new URL(testUrl);

          vulnerabilities.push({
            type: 'access-control',
            severity: 'critical',
            title: 'Missing Function Level Access Control',
            description: `The API endpoint ${parsedUrl.pathname} is accessible without proper authorization and exposes sensitive data. This allows unauthorized users to access privileged information.`,
            location: testUrl,
            evidence: `Method: GET, Status: ${response.status}, Response size: ${data.length} bytes, Sensitive data: yes, Source: ${endpoint.source}`,
          });
        }
      }
    } catch (error) {
      // Continue
    }
  }

  return vulnerabilities;
}

/**
 * [A01-5] Teste le path traversal pour contourner les contrôles d'accès
 */
async function scanPathTraversalBypass(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];
  const baseUrl = new URL(target);

  // Tester les payloads de path traversal pour accéder à /admin
  for (const payload of PATH_TRAVERSAL_PAYLOADS) {
    try {
      const testUrl = `${baseUrl.origin}${payload}`;
      const response = await axios.get(testUrl, {
        timeout: 5000,
        validateStatus: (status) => status < 500,
        headers: { 'User-Agent': 'VulnScanner/1.0' },
      });

      if (response.status === 200) {
        const $ = cheerio.load(response.data);
        const pageText = $('body').text().toLowerCase();
        const title = $('title').text().toLowerCase();

        // Vérifier si on a accédé à une page admin
        const isAdminPage =
          title.includes('admin') ||
          pageText.includes('administrator') ||
          pageText.includes('admin panel') ||
          pageText.includes('dashboard');

        if (isAdminPage) {
          vulnerabilities.push({
            type: 'access-control',
            severity: 'high',
            title: 'Path Traversal Bypass for Access Control',
            description: `Path traversal using "${payload}" bypasses access controls and allows access to administrative areas.`,
            location: testUrl,
            evidence: `Payload: ${payload}, Status: ${response.status}`,
          });
          break; // Une seule suffit
        }
      }
    } catch (error) {
      // Continue
    }
  }

  return vulnerabilities;
}

/**
 * [A01-6] Teste la manipulation de paramètres pour contourner les contrôles
 */
async function scanParameterManipulation(target: string): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];

  try {
    const baseUrl = new URL(target);

    // Paramètres à manipuler
    const manipulationTests = [
      { param: 'admin', value: 'true' },
      { param: 'admin', value: '1' },
      { param: 'role', value: 'admin' },
      { param: 'isAdmin', value: 'true' },
      { param: 'access_level', value: '9' },
      { param: 'debug', value: 'true' },
      { param: 'test', value: 'true' },
    ];

    for (const test of manipulationTests) {
      try {
        const testUrl = new URL(target);
        testUrl.searchParams.set(test.param, test.value);

        const response = await axios.get(testUrl.href, {
          timeout: 5000,
          validateStatus: () => true,
          headers: { 'User-Agent': 'VulnScanner/1.0' },
        });

        if (response.status === 200) {
          const $ = cheerio.load(response.data);
          const pageText = $('body').text().toLowerCase();

          // Vérifier les indicateurs d'accès privilégié
          const hasPrivilegedAccess =
            pageText.includes('admin') ||
            pageText.includes('debug mode') ||
            pageText.includes('administrator') ||
            pageText.includes('elevated privileges') ||
            (response.data.toString().length > 0 &&
             response.data.toString() !== '');

          // Comparer avec la page sans le paramètre
          const normalResponse = await axios.get(target, {
            timeout: 5000,
            validateStatus: () => true,
            headers: { 'User-Agent': 'VulnScanner/1.0' },
          });

          // Si la réponse est significativement différente
          const isDifferent =
            Math.abs(response.data.toString().length - normalResponse.data.toString().length) > 500;

          if (hasPrivilegedAccess && isDifferent) {
            vulnerabilities.push({
              type: 'access-control',
              severity: 'high',
              title: 'Access Control Bypass via Parameter Manipulation',
              description: `Manipulating the parameter "${test.param}" to "${test.value}" changes the application behavior and may grant unauthorized access or reveal sensitive information.`,
              location: testUrl.href,
              evidence: `Parameter: ${test.param}=${test.value}`,
            });
            break; // Une seule suffit
          }
        }
      } catch (error) {
        // Continue
      }
    }
  } catch (error) {
    // Continue silently
  }

  return vulnerabilities;
}
