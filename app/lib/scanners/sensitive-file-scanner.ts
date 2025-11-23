// src/scanners/hiddenFilesAdvanced.ts
import axios, { AxiosResponse } from 'axios';
import { HiddenFileVulnerability } from '../types';

// ============================================
// CONFIGURATION
// ============================================
const CONFIG = {
  CONCURRENCY: 10,           // Requêtes simultanées
  TIMEOUT: 3000,            // Timeout par requête (ms) - réduit de 5s à 3s
  MIN_CONTENT_SIZE: 10,     // Taille minimale pour être valide
  MAX_REDIRECTS: 0,         // Pas de redirections
  RETRY_ATTEMPTS: 1,        // Tentatives en cas d'erreur - réduit de 2 à 1
  RATE_LIMIT_DELAY: 50,     // Délai entre chunks (ms) - réduit de 100ms à 50ms
};

// ============================================
// LISTE EXHAUSTIVE DE FICHIERS SENSIBLES
// ============================================
const SENSITIVE_PATHS = [
  // ==================== CONFIGURATION FILES ====================
  '.env',
  '.env.local',
  '.env.development',
  '.env.production',
  '.env.staging',
  '.env.test',
  '.env.backup',
  '.env.old',
  '.env.save',
  'env',
  'env.txt',

  // Git files
  '.git/config',
  '.git/HEAD',
  '.git/index',
  '.git/description',
  '.git/logs/HEAD',
  '.git/logs/refs/heads/master',
  '.git/logs/refs/heads/main',
  '.git/logs/refs/heads/dev',
  '.git/refs/heads/master',
  '.git/refs/heads/main',
  '.git/refs/heads/dev',
  '.git/objects/info/packs',
  '.gitignore',
  '.gitmodules',
  '.gitattributes',

  // Apache/Nginx
  '.htaccess',
  '.htpasswd',
  '.htusers',
  'htaccess.txt',
  'htpasswd.txt',

  // Web server configs
  'web.config',
  'web.config.bak',
  'Web.config',
  'nginx.conf',
  'httpd.conf',
  'apache2.conf',

  // Application configs
  'config.xml',
  'config.json',
  'config.yml',
  'config.yaml',
  'configuration.xml',
  'settings.xml',
  'settings.json',
  'application.properties',
  'application.yml',
  'application.yaml',
  'application-prod.yml',
  'appsettings.json',
  'appsettings.Development.json',
  'appsettings.Production.json',

  // Package managers
  'composer.json',
  'composer.lock',
  'package.json',
  'package-lock.json',
  'yarn.lock',
  'Gemfile',
  'Gemfile.lock',
  'requirements.txt',
  'Pipfile',
  'Pipfile.lock',
  'pom.xml',
  'build.gradle',

  // Docker & Container
  'Dockerfile',
  'docker-compose.yml',
  'docker-compose.yaml',
  '.dockerignore',
  'Makefile',

  // Cloud & Infrastructure
  'terraform.tfstate',
  'terraform.tfstate.backup',
  'terraform.tfvars',
  '.terraform/terraform.tfstate',
  'ansible.cfg',
  'inventory.ini',
  'hosts.yml',
  'kubernetes.yml',
  'k8s-config.yml',

  // AWS
  '.aws/config',
  '.aws/credentials',
  'aws-credentials.json',
  'aws.json',

  // SSH & Keys
  '.ssh/id_rsa',
  '.ssh/id_rsa.pub',
  '.ssh/id_dsa',
  '.ssh/authorized_keys',
  '.ssh/known_hosts',
  'id_rsa',
  'id_dsa',
  'privatekey.pem',
  'publickey.pem',

  // API Keys & Secrets
  'api-keys.txt',
  'api_keys.txt',
  'apikeys.txt',
  'keys.txt',
  'tokens.txt',
  'secrets.txt',
  'credentials.txt',
  'credentials.json',
  'secrets.json',
  'firebase-config.json',
  'google-credentials.json',
  'service-account.json',
  '.npmrc',
  '.pypirc',

  // ==================== BACKUP FILES ====================
  // Compressed backups
  'backup.zip',
  'backup.tar',
  'backup.tar.gz',
  'backup.tgz',
  'backup.rar',
  'backup.7z',
  'site-backup.zip',
  'site-backup.tar.gz',
  'web-backup.zip',
  'www.zip',
  'www.tar.gz',
  'public_html.zip',
  'public_html.tar.gz',
  'httpdocs.zip',
  'website.zip',
  'backup_2023.zip',
  'backup_2024.zip',
  '2023.zip',
  '2024.zip',
  'old.zip',

  // SQL backups
  'database.sql',
  'database.sql.gz',
  'database.sql.bak',
  'db.sql',
  'db.sql.gz',
  'mysql.sql',
  'mysql.sql.gz',
  'dump.sql',
  'dump.sql.gz',
  'backup.sql',
  'backup.sql.gz',
  'db_backup.sql',
  'mysqldump.sql',
  'postgresql.sql',
  'postgres.sql',
  'mongo.dump',

  // Database files
  'database.sqlite',
  'database.sqlite3',
  'db.sqlite',
  'app.db',
  'data.db',
  'sqlite.db',

  // ==================== IDE & EDITOR FILES ====================
  // IntelliJ IDEA
  '.idea/workspace.xml',
  '.idea/modules.xml',
  '.idea/vcs.xml',
  '.idea/dataSources.xml',
  '.idea/.name',

  // VS Code
  '.vscode/settings.json',
  '.vscode/launch.json',
  '.vscode/tasks.json',
  '.vscode/extensions.json',

  // Eclipse
  '.project',
  '.classpath',
  '.settings/org.eclipse.core.resources.prefs',

  // NetBeans
  'nbproject/project.properties',
  'nbproject/private/private.properties',

  // Vim
  '.vimrc',
  '.viminfo',

  // ==================== LOG FILES ====================
  'error.log',
  'errors.log',
  'error_log',
  'debug.log',
  'access.log',
  'access_log',
  'server.log',
  'application.log',
  'app.log',
  'laravel.log',
  'symfony.log',
  'django.log',
  'rails.log',
  'npm-debug.log',
  'yarn-error.log',
  'composer.log',

  // Log directories
  'logs/error.log',
  'logs/errors.log',
  'logs/access.log',
  'logs/laravel.log',
  'storage/logs/laravel.log',
  'var/log/apache2/error.log',
  'var/log/nginx/error.log',
  'log/development.log',
  'log/production.log',

  // ==================== VERSION CONTROL ====================
  // SVN
  '.svn/entries',
  '.svn/wc.db',
  '.svn/all-wcprops',

  // Mercurial
  '.hg/store/00changelog.i',
  '.hg/requires',
  '.hgignore',

  // CVS
  'CVS/Entries',
  'CVS/Root',

  // ==================== ADMIN INTERFACES ====================
  'admin/',
  'admin',
  'admin.php',
  'admin.html',
  'admin/index.php',
  'admin/login.php',
  'admin/dashboard.php',
  'administrator/',
  'administrator',
  'administration/',
  'cpanel/',
  'cpanel',
  'webmail/',
  'webmail',

  // WordPress
  'wp-admin/',
  'wp-login.php',
  'wp-config.php',
  'wp-config.php.bak',
  'wp-config.php~',
  'wp-config.php.old',
  'wp-config.php.save',
  'wp-config.old',
  'wp-content/debug.log',
  'wp-includes/',
  'xmlrpc.php',

  // Joomla
  'administrator/index.php',
  'configuration.php',
  'configuration.php-dist',

  // Drupal
  'sites/default/settings.php',
  'sites/default/settings.local.php',

  // Database Admin
  'phpmyadmin/',
  'phpMyAdmin/',
  'pma/',
  'mysql/',
  'myadmin/',
  'adminer.php',
  'adminer-4.8.1.php',
  'adminer-4.8.0.php',
  'adminer/',
  'db/',
  'dbadmin/',

  // ==================== SENSITIVE DIRECTORIES ====================
  'backups/',
  'backup/',
  'old/',
  'temp/',
  'tmp/',
  'sql/',
  'database/',
  'db/',
  'data/',
  'uploads/',
  'files/',
  'documents/',
  'docs/',
  'private/',
  'secret/',
  'confidential/',
  'test/',
  'tests/',
  'demo/',
  'dev/',
  'staging/',

  // ==================== PHP SPECIFIC ====================
  'phpinfo.php',
  'info.php',
  'test.php',
  'tests.php',
  'debug.php',
  'shell.php',
  'c99.php',
  'r57.php',
  'webshell.php',
  'backdoor.php',

  // ==================== OTHER SENSITIVE ====================
  'robots.txt',
  'sitemap.xml',
  'sitemap_index.xml',
  'crossdomain.xml',
  'clientaccesspolicy.xml',
  '.DS_Store',
  'Thumbs.db',
  'desktop.ini',
  'CHANGELOG.md',
  'CHANGELOG.txt',
  'README.md',
  'TODO.txt',
  'LICENSE',
  'VERSION',
  'INSTALL',
  'composer.phar',

  // Server info
  'server-status',
  'server-info',
  'status',
  'info',

  // Session files
  'sess_',
  'sessions/',
  'tmp/sess_',
];

// ==================== BACKUP VARIATIONS ====================
const COMMON_FILES = [
  'index.php',
  'index.html',
  'config.php',
  'database.php',
  'db.php',
  'admin.php',
  'login.php',
  'upload.php',
  'user.php',
  'api.php',
  'functions.php',
  'common.php',
  'settings.php',
];

const BACKUP_EXTENSIONS = [
  '.bak',
  '.backup',
  '.old',
  '.orig',
  '.original',
  '.save',
  '.saved',
  '.swp',
  '.swo',
  '.tmp',
  '~',
  '.1',
  '.2',
  '.copy',
  '.dist',
  '.default',
  '.sample',
  '-old',
  '-backup',
  '_backup',
  '_old',
];

/**
 * Génère les variations de backup pour fichiers communs
 */
function generateBackupVariations(): string[] {
  const variations: string[] = [];

  for (const file of COMMON_FILES) {
    for (const ext of BACKUP_EXTENSIONS) {
      variations.push(file + ext);

      // Variante avec double extension
      const parts = file.split('.');
      if (parts.length > 1) {
        // ex: config.php.bak
        variations.push(file + ext);
        // ex: config.bak.php
        variations.push(`${parts[0]}${ext}.${parts[1]}`);
      }
    }
  }

  return variations;
}

// ============================================
// SCANNER PRINCIPAL
// ============================================
export async function scanHiddenFiles(
    target: string,
    options: {
      concurrency?: number;
      includeBackupVariations?: boolean;
      verbose?: boolean;
    } = {}
): Promise<HiddenFileVulnerability[]> {
  const vulnerabilities: HiddenFileVulnerability[] = [];
  const {
    concurrency = CONFIG.CONCURRENCY,
    includeBackupVariations = true,
    verbose = true,
  } = options;

  try {
    const baseUrl = target.endsWith('/') ? target.slice(0, -1) : target;

    // Génère la liste complète
    let allPaths = [...SENSITIVE_PATHS];

    if (includeBackupVariations) {
      allPaths = [...allPaths, ...generateBackupVariations()];
    }

    // Déduplique
    allPaths = [...new Set(allPaths)];

    if (verbose) {
      console.log(`\n[Hidden Files Scanner] Starting scan...`);
      console.log(`   Target: ${baseUrl}`);
      console.log(`   Paths to test: ${allPaths.length}`);
      console.log(`   Concurrency: ${concurrency}`);
      console.log('');
    }

    let testedCount = 0;
    let foundCount = 0;

    // Test en parallèle par chunks
    for (let i = 0; i < allPaths.length; i += concurrency) {
      const chunk = allPaths.slice(i, i + concurrency);

      const promises = chunk.map(path =>
          testPathWithRetry(baseUrl, path, CONFIG.RETRY_ATTEMPTS)
      );

      const results = await Promise.allSettled(promises);

      results.forEach((result, index) => {
        testedCount++;

        if (result.status === 'fulfilled' && result.value) {
          foundCount++;
          vulnerabilities.push(result.value);

          if (verbose) {
            const vuln = result.value;
            console.log(`   [${vuln.severity.toUpperCase()}] ${chunk[index]} (${vuln.status})`);
          }
        }
      });

      // Progress indicator
      if (verbose && testedCount % 50 === 0) {
        console.log(`   Progress: ${testedCount}/${allPaths.length} (${foundCount} found)`);
      }

      // Rate limiting
      if (i + concurrency < allPaths.length) {
        await sleep(CONFIG.RATE_LIMIT_DELAY);
      }
    }

    if (verbose) {
      console.log(`\n   [SUMMARY]`);
      console.log(`      Paths tested: ${testedCount}`);
      console.log(`      Vulnerabilities found: ${foundCount}`);
      console.log(`      By severity:`);

      const bySeverity = {
        critical: vulnerabilities.filter(v => v.severity === 'critical').length,
        high: vulnerabilities.filter(v => v.severity === 'high').length,
        medium: vulnerabilities.filter(v => v.severity === 'medium').length,
        low: vulnerabilities.filter(v => v.severity === 'low').length,
      };

      console.log(`         Critical: ${bySeverity.critical}`);
      console.log(`         High: ${bySeverity.high}`);
      console.log(`         Medium: ${bySeverity.medium}`);
      console.log(`         Low: ${bySeverity.low}`);
      console.log('');
    }

  } catch (error) {
    console.error('[Hidden Files Scanner] Error:', error);
  }

  return vulnerabilities;
}

// ============================================
// TEST D'UN PATH AVEC RETRY
// ============================================
async function testPathWithRetry(
    baseUrl: string,
    path: string,
    retries: number
): Promise<HiddenFileVulnerability | null> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await testPath(baseUrl, path);
    } catch (error) {
      if (attempt === retries) {
        return null;
      }
      await sleep(500 * (attempt + 1)); // Backoff exponentiel
    }
  }
  return null;
}

// ============================================
// TEST D'UN PATH INDIVIDUEL
// ============================================
async function testPath(
    baseUrl: string,
    path: string
): Promise<HiddenFileVulnerability | null> {
  const testUrl = `${baseUrl}/${path}`;

  try {
    const response = await axios.get(testUrl, {
      timeout: CONFIG.TIMEOUT,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': '*/*',
      },
      validateStatus: (status) => status < 500,
      maxRedirects: CONFIG.MAX_REDIRECTS,
      responseType: path.endsWith('/') ? 'text' : 'arraybuffer',
    });

    // ============================================
    // VÉRIFICATION 1: Status Code
    // ============================================
    if (response.status !== 200) {
      return null;
    }

    // ============================================
    // VÉRIFICATION 2: Taille du contenu
    // ============================================
    const contentLength = response.data?.length || 0;
    if (contentLength < CONFIG.MIN_CONTENT_SIZE) {
      return null;
    }

    // Convertit buffer en string si nécessaire
    const content = typeof response.data === 'string'
        ? response.data
        : Buffer.from(response.data).toString('utf8');

    // ============================================
    // VÉRIFICATION 3: Détection 404 custom
    // ============================================
    if (isCustom404Page(content)) {
      return null;
    }

    // ============================================
    // VÉRIFICATION 4: Directory Listing & Admin Interfaces
    // ============================================
    if (path.endsWith('/')) {
      // Vérifie d'abord si c'est un directory listing
      if (isDirectoryListing(content)) {
        return createVulnerability(
            testUrl,
            path,
            response.status,
            'high',
            'Directory Listing Enabled',
            'Directory listing is publicly accessible',
            content,
            'Disable directory listing in web server configuration (Options -Indexes for Apache)'
        );
      }

      // Vérifie si c'est une interface admin accessible
      if (isAdminInterface(path, content)) {
        const severity = getSeverityForPath(path);
        return createVulnerability(
            testUrl,
            path,
            response.status,
            severity,
            'Exposed Administrative Interface',
            `Administrative interface is publicly accessible: ${path}`,
            generateEvidence(path, content, response.status, contentLength),
            getRecommendationForPath(path)
        );
      }

      return null;
    }

    // ============================================
    // VÉRIFICATION 5: Validation spécifique par type
    // ============================================
    const validationResult = validateFileContent(path, content);

    if (!validationResult.isValid) {
      return null;
    }

    // ============================================
    // VULNÉRABILITÉ CONFIRMÉE !
    // ============================================
    const severity = getSeverityForPath(path);
    const fileType = getFileType(path);
    const evidence = generateEvidence(path, content, response.status, contentLength);

    return createVulnerability(
        testUrl,
        path,
        response.status,
        severity,
        `Exposed ${fileType}`,
        `Sensitive ${fileType} is publicly accessible: ${path}`,
        evidence,
        getRecommendationForPath(path)
    );

  } catch (error) {
    // Erreurs réseau, timeouts, etc. → pas une vulnérabilité
    return null;
  }
}

// ============================================
// VALIDATION DU CONTENU PAR TYPE
// ============================================
interface ValidationResult {
  isValid: boolean;
  reason?: string;
}

function validateFileContent(path: string, content: string): ValidationResult {
  const lowerPath = path.toLowerCase();
  const lowerContent = content.toLowerCase();

  // ==================== .ENV FILES ====================
  if (lowerPath.includes('.env')) {
    // Format: KEY=value
    const envPattern = /^[A-Z_][A-Z0-9_]*\s*=\s*.+$/m;
    if (!envPattern.test(content)) {
      return { isValid: false, reason: 'Not a valid ENV format' };
    }

    // Doit contenir au moins une variable sensible
    const sensitiveKeywords = [
      'password', 'secret', 'key', 'token', 'api',
      'database', 'db_', 'aws', 'stripe', 'mail',
    ];

    if (!sensitiveKeywords.some(kw => lowerContent.includes(kw))) {
      return { isValid: false, reason: 'No sensitive variables found' };
    }

    return { isValid: true };
  }

  // ==================== GIT FILES ====================
  if (lowerPath.includes('.git/')) {
    const gitIndicators = [
      'ref:', '[core]', '[remote', 'repositoryformatversion',
      'bare = false', 'logallrefupdates',
    ];

    if (!gitIndicators.some(indicator => lowerContent.includes(indicator))) {
      return { isValid: false, reason: 'Not a valid Git file' };
    }

    return { isValid: true };
  }

  // ==================== SQL FILES ====================
  if (lowerPath.includes('.sql')) {
    const sqlKeywords = [
      'create table', 'insert into', 'drop table',
      'alter table', 'select ', 'update ', 'delete from',
      'database', 'mysqldump', 'postgresql',
    ];

    if (!sqlKeywords.some(kw => lowerContent.includes(kw))) {
      return { isValid: false, reason: 'Not a valid SQL dump' };
    }

    // Doit être assez long pour être un vrai dump
    if (content.length < 100) {
      return { isValid: false, reason: 'SQL file too small' };
    }

    return { isValid: true };
  }

  // ==================== JSON FILES ====================
  if (lowerPath.endsWith('.json')) {
    try {
      const parsed = JSON.parse(content);

      // Doit contenir au moins une clé
      if (Object.keys(parsed).length === 0) {
        return { isValid: false, reason: 'Empty JSON' };
      }

      return { isValid: true };
    } catch {
      return { isValid: false, reason: 'Invalid JSON' };
    }
  }

  // ==================== HTACCESS ====================
  if (lowerPath.includes('.htaccess')) {
    const htaccessKeywords = [
      'rewriterule', 'rewritecond', 'authtype',
      'authname', 'require valid-user', 'deny from',
      'allow from', 'options ', 'errordocument',
    ];

    if (!htaccessKeywords.some(kw => lowerContent.includes(kw))) {
      return { isValid: false, reason: 'Not a valid .htaccess file' };
    }

    return { isValid: true };
  }

  // ==================== WEB.CONFIG ====================
  if (lowerPath.includes('web.config')) {
    if (!lowerContent.includes('<configuration>') ||
        !lowerContent.includes('</configuration>')) {
      return { isValid: false, reason: 'Not a valid web.config' };
    }

    return { isValid: true };
  }

  // ==================== LOG FILES ====================
  if (lowerPath.includes('log')) {
    const logIndicators = [
      'error', 'warning', 'info', 'debug', 'fatal',
      'exception', 'stack trace', 'timestamp', '[',
    ];

    if (!logIndicators.some(indicator => lowerContent.includes(indicator))) {
      return { isValid: false, reason: 'Not a valid log file' };
    }

    return { isValid: true };
  }

  // ==================== WORDPRESS FILES ====================
  if (lowerPath.includes('wp-config')) {
    const wpIndicators = [
      'db_name', 'db_user', 'db_password', 'db_host',
      'auth_key', 'secure_auth_key', 'wp_debug',
    ];

    if (!wpIndicators.some(indicator => lowerContent.includes(indicator))) {
      return { isValid: false, reason: 'Not a valid wp-config.php' };
    }

    return { isValid: true };
  }

  // ==================== SSH KEYS ====================
  if (lowerPath.includes('id_rsa') || lowerPath.includes('privatekey')) {
    if (!content.includes('-----BEGIN') || !content.includes('PRIVATE KEY')) {
      return { isValid: false, reason: 'Not a valid private key' };
    }

    return { isValid: true };
  }

  // ==================== AWS CREDENTIALS ====================
  if (lowerPath.includes('.aws')) {
    const awsIndicators = [
      'aws_access_key_id', 'aws_secret_access_key',
      '[default]', '[profile', 'region =',
    ];

    if (!awsIndicators.some(indicator => lowerContent.includes(indicator))) {
      return { isValid: false, reason: 'Not valid AWS credentials' };
    }

    return { isValid: true };
  }

  // ==================== BACKUP ARCHIVES ====================
  if (lowerPath.match(/\.(zip|tar|gz|rar|7z)$/)) {
    // Vérifie les magic bytes
    const buffer = Buffer.from(content, 'binary');

    // ZIP: PK\x03\x04
    if (buffer[0] === 0x50 && buffer[1] === 0x4B) {
      return { isValid: true };
    }

    // TAR: ustar
    if (content.includes('ustar')) {
      return { isValid: true };
    }

    // GZIP: \x1f\x8b
    if (buffer[0] === 0x1F && buffer[1] === 0x8B) {
      return { isValid: true };
    }

    // RAR: Rar!
    if (content.startsWith('Rar!')) {
      return { isValid: true };
    }

    return { isValid: false, reason: 'Not a valid archive' };
  }

  // ==================== DEFAULT: Si incertain, valider ====================
  return { isValid: true };
}

// ============================================
// DÉTECTION PAGE 404 CUSTOM
// ============================================
function isCustom404Page(content: string): boolean {
  const lowerContent = content.toLowerCase();

  // Patterns communs de pages 404
  const notFoundPatterns = [
    '404',
    'not found',
    'page not found',
    'file not found',
    'error 404',
    'page introuvable',
    'page non trouvée',
    'cannot be found',
    'does not exist',
    "n'existe pas",
  ];

  // Compte les occurrences
  let matches = 0;
  for (const pattern of notFoundPatterns) {
    if (lowerContent.includes(pattern)) {
      matches++;
    }
  }

  // Si 2+ patterns, probablement une page 404
  if (matches >= 2) {
    return true;
  }

  // Vérifie le titre
  const titleMatch = content.match(/<title>(.*?)<\/title>/i);
  if (titleMatch) {
    const title = titleMatch[1].toLowerCase();
    if (notFoundPatterns.some(pattern => title.includes(pattern))) {
      return true;
    }
  }

  // Vérifie h1
  const h1Match = content.match(/<h1[^>]*>(.*?)<\/h1>/i);
  if (h1Match) {
    const h1 = h1Match[1].toLowerCase();
    if (notFoundPatterns.some(pattern => h1.includes(pattern))) {
      return true;
    }
  }

  return false;
}

// ============================================
// DÉTECTION DIRECTORY LISTING
// ============================================
function isDirectoryListing(content: string): boolean {
  const indicators = [
    'Index of /',
    'Directory listing for',
    'Parent Directory',
    '<title>Index of',
    'apache.*directory index',
    'nginx.*autoindex',
  ];

  return indicators.some(indicator =>
      new RegExp(indicator, 'i').test(content)
  );
}

// ============================================
// DÉTECTION INTERFACE ADMIN
// ============================================
function isAdminInterface(path: string, content: string): boolean {
  const lowerPath = path.toLowerCase();
  const lowerContent = content.toLowerCase();

  // Chemins admin connus
  const adminPaths = [
    'admin',
    'administrator',
    'administration',
    'cpanel',
    'webmail',
    'phpmyadmin',
    'myadmin',
    'adminer',
    'dbadmin',
  ];

  // Vérifie si le chemin contient un mot-clé admin
  const isAdminPath = adminPaths.some(keyword => lowerPath.includes(keyword));

  if (!isAdminPath) {
    return false;
  }

  // Indicateurs d'interface admin dans le contenu
  const adminIndicators = [
    'login',
    'username',
    'password',
    'sign in',
    'log in',
    'authentication',
    'admin panel',
    'dashboard',
    'control panel',
    'administration',
    'type="password"',
    'input.*password',
    'form.*login',
  ];

  // Compte les correspondances
  let matches = 0;
  for (const indicator of adminIndicators) {
    if (new RegExp(indicator, 'i').test(lowerContent)) {
      matches++;
    }
  }

  // Si au moins 2 indicateurs sont présents, c'est probablement une interface admin
  return matches >= 2;
}

// ============================================
// GÉNÉRATION EVIDENCE
// ============================================
function generateEvidence(
    path: string,
    content: string,
    status: number,
    size: number
): string {
  let evidence = `HTTP ${status} - ${size} bytes\n\n`;

  // Extrait un aperçu du contenu (premiers 200 caractères)
  const preview = content.substring(0, 200);
  const sanitizedPreview = preview
      .replace(/[^\x20-\x7E\n\r]/g, '.') // Remplace caractères non-imprimables
      .trim();

  evidence += `Content Preview:\n${sanitizedPreview}`;

  if (content.length > 200) {
    evidence += '\n[... truncated ...]';
  }

  // Ajoute des infos spécifiques par type
  if (path.includes('.env')) {
    const envVars = content.match(/^[A-Z_][A-Z0-9_]*=/gm);
    if (envVars) {
      evidence += `\n\nEnvironment Variables Found: ${envVars.length}`;
      evidence += `\nSample: ${envVars.slice(0, 5).join(', ')}`;
    }
  }

  if (path.includes('.sql')) {
    const tables = content.match(/CREATE TABLE [`'"]?(\w+)[`'"]?/gi);
    if (tables) {
      evidence += `\n\nDatabase Tables Found: ${tables.length}`;
    }
  }

  return evidence;
}

// ============================================
// DÉTERMINATION SÉVÉRITÉ
// ============================================
function getSeverityForPath(path: string): 'low' | 'medium' | 'high' | 'critical' {
  const lowerPath = path.toLowerCase();

  // CRITICAL - Credentials, keys, sensitive data
  const criticalPatterns = [
    '.env',
    '.htpasswd',
    'database.sql',
    'backup.sql',
    'db.sql',
    'dump.sql',
    'credentials',
    'id_rsa',
    'privatekey',
    '.aws/credentials',
    'secrets',
    'api-keys',
    'tokens',
  ];

  if (criticalPatterns.some(pattern => lowerPath.includes(pattern))) {
    return 'critical';
  }

  // HIGH - Config files, source control, sensitive info
  const highPatterns = [
    '.git/config',
    '.git/index',
    '.htaccess',
    'web.config',
    'wp-config',
    'config.php',
    'database.php',
    'application.properties',
    'appsettings.json',
    'composer.json',
  ];

  if (highPatterns.some(pattern => lowerPath.includes(pattern))) {
    return 'high';
  }

  // MEDIUM - Logs, admin panels, backups
  const mediumPatterns = [
    'log',
    'admin',
    'backup',
    'old',
    '.git/',
    'phpmyadmin',
    'error',
  ];

  if (mediumPatterns.some(pattern => lowerPath.includes(pattern))) {
    return 'medium';
  }

  // LOW - Everything else
  return 'low';
}

// ============================================
// CATÉGORISATION TYPE DE FICHIER
// ============================================
function getFileType(path: string): string {
  const lowerPath = path.toLowerCase();

  if (lowerPath.includes('.env')) return 'Environment Configuration File';
  if (lowerPath.includes('.git')) return 'Git Repository File';
  if (lowerPath.includes('.ht')) return 'Apache Configuration File';
  if (lowerPath.includes('.sql')) return 'Database Backup File';
  if (lowerPath.includes('backup') || lowerPath.match(/\.(zip|tar|gz|rar|7z)$/)) return 'Backup Archive';
  if (lowerPath.includes('log')) return 'Log File';
  if (lowerPath.includes('admin')) return 'Administrative Interface';
  if (lowerPath.includes('config')) return 'Configuration File';
  if (lowerPath.includes('.aws') || lowerPath.includes('.ssh')) return 'Cloud Credentials';
  if (lowerPath.includes('wp-')) return 'WordPress File';
  if (lowerPath.includes('composer') || lowerPath.includes('package')) return 'Dependency File';
  if (lowerPath.includes('docker')) return 'Container Configuration';
  if (lowerPath.includes('terraform') || lowerPath.includes('ansible')) return 'Infrastructure as Code';

  return 'Sensitive File';
}

// ============================================
// RECOMMANDATIONS PAR TYPE
// ============================================
function getRecommendationForPath(path: string): string {
  const lowerPath = path.toLowerCase();

  if (lowerPath.includes('.env')) {
    return 'Environment files should NEVER be accessible publicly. Add to .gitignore and configure web server to deny access. Use environment variables injection instead.';
  }

  if (lowerPath.includes('.git')) {
    return 'Git repositories should never be deployed to production. Remove .git directory or configure web server to deny access to all .git paths.';
  }

  if (lowerPath.includes('.sql')) {
    return 'Database backups contain sensitive data and should never be web-accessible. Store backups in secure, non-public locations with restricted access.';
  }

  if (lowerPath.includes('admin')) {
    return 'Administrative interfaces should be protected with authentication and IP whitelisting. Consider using a non-standard URL path and implementing 2FA.';
  }

  if (lowerPath.includes('log')) {
    return 'Log files may contain sensitive information and should not be publicly accessible. Configure log rotation and store logs outside web root.';
  }

  if (lowerPath.includes('.aws') || lowerPath.includes('.ssh')) {
    return 'Cloud credentials and SSH keys should NEVER be stored in web-accessible locations. Use proper secrets management (AWS Secrets Manager, HashiCorp Vault, etc.).';
  }

  if (lowerPath.includes('backup')) {
    return 'Backups should be stored in secure, offline locations with encryption. Never store backups in web-accessible directories.';
  }

  return 'Sensitive files should be removed from production environments or access should be restricted using web server configuration.';
}

// ============================================
// CRÉATION VULNÉRABILITÉ
// ============================================
function createVulnerability(
    url: string,
    path: string,
    status: number,
    severity: 'low' | 'medium' | 'high' | 'critical',
    title: string,
    description: string,
    evidence: string,
    recommendation: string
): HiddenFileVulnerability {
  return {
    type: 'information_disclosure',
    severity,
    status,
    title,
    description,
    path: url,
    evidence,
    recommendation,
  };
}

// ============================================
// HELPER: Sleep
// ============================================
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================
// EXPORT
// ============================================
export default scanHiddenFiles;
