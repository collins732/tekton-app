'use client';

import { useState, useEffect } from 'react';

interface APIKey {
  key_id: string;
  name: string;
  key_preview: string;
  created_at: number;
  last_used_at: number | null;
  status: 'active' | 'inactive';
  requests_count: number;
}

interface Stats {
  total_keys: number;
  active_keys: number;
  total_requests: number;
}

const CODE_EXAMPLES = {
  curl: `curl -X POST https://api.tekton.io/v1/scan \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "url": "https://example.com",
    "scan_types": ["port", "xss", "sqli"]
  }'`,
  python: `import requests

url = "https://api.tekton.io/v1/scan"
headers = {
    "Authorization": "Bearer YOUR_API_KEY",
    "Content-Type": "application/json"
}
data = {
    "url": "https://example.com",
    "scan_types": ["port", "xss", "sqli"]
}

response = requests.post(url, headers=headers, json=data)
print(response.json())`,
  javascript: `const response = await fetch('https://api.tekton.io/v1/scan', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer YOUR_API_KEY',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    url: 'https://example.com',
    scan_types: ['port', 'xss', 'sqli']
  })
});

const data = await response.json();
console.log(data);`,
  php: `<?php
$url = 'https://api.tekton.io/v1/scan';
$headers = [
    'Authorization: Bearer YOUR_API_KEY',
    'Content-Type: application/json'
];
$data = json_encode([
    'url' => 'https://example.com',
    'scan_types' => ['port', 'xss', 'sqli']
]);

$ch = curl_init($url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$response = curl_exec($ch);
curl_close($ch);

echo $response;
?>`
};

export default function ApiKeysPage() {
  const [keys, setKeys] = useState<APIKey[]>([]);
  const [stats, setStats] = useState<Stats>({ total_keys: 0, active_keys: 0, total_requests: 0 });
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showKeyModal, setShowKeyModal] = useState(false);
  const [showConfirmModal, setShowConfirmModal] = useState<{ type: 'revoke' | 'regenerate'; keyId: string; keyName: string } | null>(null);
  const [newKeyName, setNewKeyName] = useState('');
  const [generatedKey, setGeneratedKey] = useState('');
  const [selectedLanguage, setSelectedLanguage] = useState<'curl' | 'python' | 'javascript' | 'php'>('curl');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  // Load API keys
  useEffect(() => {
    loadKeys();
  }, []);

  const loadKeys = async () => {
    try {
      const response = await fetch('/api/keys');
      if (response.ok) {
        const data = await response.json();
        setKeys(data.keys || []);
        setStats(data.stats || { total_keys: 0, active_keys: 0, total_requests: 0 });
      }
    } catch (error) {
      console.error('Failed to load API keys:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateKey = async () => {
    if (!newKeyName.trim()) return;

    setActionLoading('create');
    try {
      const response = await fetch('/api/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newKeyName.trim() })
      });

      if (response.ok) {
        const data = await response.json();
        setGeneratedKey(data.api_key);
        setShowCreateModal(false);
        setShowKeyModal(true);
        setNewKeyName('');
        loadKeys(); // Refresh list
      } else {
        const error = await response.json();
        alert(error.error || 'Failed to create API key');
      }
    } catch (error) {
      console.error('Failed to create API key:', error);
      alert('Failed to create API key');
    } finally {
      setActionLoading(null);
    }
  };

  const handleRegenerateKey = async (keyId: string) => {
    setActionLoading(keyId);
    setShowConfirmModal(null);

    try {
      const response = await fetch(`/api/keys/${keyId}`, {
        method: 'PUT'
      });

      if (response.ok) {
        const data = await response.json();
        setGeneratedKey(data.api_key);
        setShowKeyModal(true);
        loadKeys();
      } else {
        const error = await response.json();
        alert(error.error || 'Failed to regenerate API key');
      }
    } catch (error) {
      console.error('Failed to regenerate API key:', error);
      alert('Failed to regenerate API key');
    } finally {
      setActionLoading(null);
    }
  };

  const handleRevokeKey = async (keyId: string) => {
    setActionLoading(keyId);
    setShowConfirmModal(null);

    try {
      const response = await fetch(`/api/keys/${keyId}`, {
        method: 'DELETE'
      });

      if (response.ok) {
        loadKeys();
      } else {
        const error = await response.json();
        alert(error.error || 'Failed to revoke API key');
      }
    } catch (error) {
      console.error('Failed to revoke API key:', error);
      alert('Failed to revoke API key');
    } finally {
      setActionLoading(null);
    }
  };

  const copyToClipboard = (text: string, keyId: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(keyId);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const formatDate = (timestamp: number) => {
    return new Date(timestamp).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  const formatLastUsed = (timestamp: number | null) => {
    if (!timestamp) return 'Never';
    const diff = Date.now() - timestamp;
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)} minutes ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)} hours ago`;
    return formatDate(timestamp);
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="terminal-border bg-black/90 backdrop-blur p-8 text-center">
          <div className="text-purple-400 text-4xl mb-4 animate-pulse">[*]</div>
          <div className="text-lg glow-purple">LOADING API KEYS...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-5xl font-bold mb-4 glow-title">[API KEYS]</h1>
          <p className="text-xl opacity-70 mb-2">Manage your API access and integration keys</p>
          <p className="text-sm opacity-50">Use these keys to integrate TEKTON scans into your applications</p>
        </div>

        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="terminal-border bg-black/80 backdrop-blur p-6">
            <div className="text-xs opacity-50 mb-2">TOTAL KEYS</div>
            <div className="text-4xl font-bold glow-accent">{stats.total_keys}</div>
          </div>
          <div className="terminal-border bg-black/80 backdrop-blur p-6">
            <div className="text-xs opacity-50 mb-2">ACTIVE KEYS</div>
            <div className="text-4xl font-bold text-green-400">{stats.active_keys}</div>
          </div>
          <div className="terminal-border bg-black/80 backdrop-blur p-6">
            <div className="text-xs opacity-50 mb-2">TOTAL REQUESTS</div>
            <div className="text-4xl font-bold text-purple-400">{stats.total_requests.toLocaleString()}</div>
          </div>
          <div className="terminal-border bg-black/80 backdrop-blur p-6">
            <div className="text-xs opacity-50 mb-2">RATE LIMIT</div>
            <div className="text-4xl font-bold text-yellow-400">1000/h</div>
          </div>
        </div>

        {/* API Keys List */}
        <div className="terminal-border bg-black/80 backdrop-blur mb-8">
          <div className="bg-purple-900/30 px-6 py-4 border-b-2 border-purple-600 flex justify-between items-center">
            <h2 className="text-2xl font-bold glow-header">YOUR API KEYS</h2>
            <button
              onClick={() => setShowCreateModal(true)}
              className="px-4 py-2 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold transition-all"
            >
              [+ CREATE NEW KEY]
            </button>
          </div>

          <div className="p-6 space-y-4">
            {keys.length === 0 ? (
              <div className="text-center py-12 opacity-50">
                <div className="text-4xl mb-4">[#]</div>
                <div>No API keys yet. Create one to get started!</div>
              </div>
            ) : (
              keys.map((apiKey) => (
                <div
                  key={apiKey.key_id}
                  className="terminal-border bg-purple-900/10 p-6 hover:bg-purple-900/20 transition-all"
                >
                  <div className="flex justify-between items-start mb-4">
                    <div>
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="text-xl font-bold glow-accent">{apiKey.name}</h3>
                        <span className={`text-xs px-3 py-1 font-bold ${
                          apiKey.status === 'active'
                            ? 'bg-green-600 border border-green-400'
                            : 'bg-gray-600 border border-gray-400'
                        }`}>
                          {apiKey.status.toUpperCase()}
                        </span>
                      </div>
                      <div className="font-mono text-sm opacity-70 mb-2">{apiKey.key_preview}</div>
                      <div className="text-xs opacity-50">
                        Created: {formatDate(apiKey.created_at)} | Last used: {formatLastUsed(apiKey.last_used_at)}
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <button
                        onClick={() => copyToClipboard(apiKey.key_preview, apiKey.key_id)}
                        className="px-3 py-2 bg-purple-600 hover:bg-purple-500 border border-purple-400 font-bold text-xs transition-all"
                      >
                        {copiedKey === apiKey.key_id ? '[OK COPIED]' : '[COPY]'}
                      </button>
                      <button
                        onClick={() => setShowConfirmModal({ type: 'regenerate', keyId: apiKey.key_id, keyName: apiKey.name })}
                        disabled={actionLoading === apiKey.key_id}
                        className="px-3 py-2 bg-yellow-600 hover:bg-yellow-500 border border-yellow-400 font-bold text-xs transition-all disabled:opacity-50"
                      >
                        {actionLoading === apiKey.key_id ? '[...]' : '[REGENERATE]'}
                      </button>
                      <button
                        onClick={() => setShowConfirmModal({ type: 'revoke', keyId: apiKey.key_id, keyName: apiKey.name })}
                        disabled={actionLoading === apiKey.key_id}
                        className="px-3 py-2 bg-red-600 hover:bg-red-500 border border-red-400 font-bold text-xs transition-all disabled:opacity-50"
                      >
                        {actionLoading === apiKey.key_id ? '[...]' : '[REVOKE]'}
                      </button>
                    </div>
                  </div>

                  {/* Usage Stats */}
                  <div className="grid grid-cols-3 gap-4 pt-4 border-t border-purple-600">
                    <div>
                      <div className="text-xs opacity-50">TOTAL REQUESTS</div>
                      <div className="text-lg font-bold text-green-400">{apiKey.requests_count.toLocaleString()}</div>
                    </div>
                    <div>
                      <div className="text-xs opacity-50">SUCCESS RATE</div>
                      <div className="text-lg font-bold text-green-400">99.8%</div>
                    </div>
                    <div>
                      <div className="text-xs opacity-50">AVG RESPONSE</div>
                      <div className="text-lg font-bold text-purple-400">245ms</div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Code Examples */}
        <div className="terminal-border bg-black/80 backdrop-blur mb-8">
          <div className="bg-purple-900/30 px-6 py-4 border-b-2 border-purple-600">
            <h2 className="text-2xl font-bold glow-header">CODE EXAMPLES</h2>
          </div>

          <div className="p-6">
            {/* Language Selector */}
            <div className="flex gap-2 mb-4">
              {(['curl', 'python', 'javascript', 'php'] as const).map((lang) => (
                <button
                  key={lang}
                  onClick={() => setSelectedLanguage(lang)}
                  className={`px-4 py-2 font-bold transition-all ${
                    selectedLanguage === lang
                      ? 'bg-purple-600 border-2 border-purple-400'
                      : 'bg-black border-2 border-purple-600 hover:border-purple-400'
                  }`}
                >
                  [{lang.toUpperCase()}]
                </button>
              ))}
            </div>

            {/* Code Block */}
            <div className="relative">
              <button
                onClick={() => copyToClipboard(CODE_EXAMPLES[selectedLanguage], 'code-example')}
                className="absolute top-4 right-4 px-3 py-1 bg-purple-600 hover:bg-purple-500 border border-purple-400 font-bold text-xs transition-all z-10"
              >
                {copiedKey === 'code-example' ? '[OK COPIED]' : '[COPY]'}
              </button>
              <pre className="bg-black border-2 border-purple-600 p-6 overflow-x-auto font-mono text-sm text-green-400">
                {CODE_EXAMPLES[selectedLanguage]}
              </pre>
            </div>
          </div>
        </div>

        {/* API Documentation */}
        <div className="terminal-border bg-black/80 backdrop-blur">
          <div className="bg-purple-900/30 px-6 py-4 border-b-2 border-purple-600">
            <h2 className="text-2xl font-bold glow-header">API ENDPOINTS</h2>
          </div>

          <div className="p-6 space-y-4">
            {[
              {
                method: 'POST',
                endpoint: '/v1/scan',
                description: 'Initiate a new vulnerability scan',
                color: 'text-green-400'
              },
              {
                method: 'GET',
                endpoint: '/v1/scan/:id',
                description: 'Retrieve scan results by ID',
                color: 'text-blue-400'
              },
              {
                method: 'GET',
                endpoint: '/v1/scans',
                description: 'List all your scans with pagination',
                color: 'text-blue-400'
              },
              {
                method: 'DELETE',
                endpoint: '/v1/scan/:id',
                description: 'Delete a scan and its results',
                color: 'text-red-400'
              },
              {
                method: 'GET',
                endpoint: '/v1/usage',
                description: 'Get your current token usage and limits',
                color: 'text-blue-400'
              }
            ].map((endpoint, index) => (
              <div key={index} className="terminal-border bg-purple-900/10 p-4 hover:bg-purple-900/20 transition-all">
                <div className="flex items-center gap-4 mb-2">
                  <span className={`font-bold ${endpoint.color} text-sm px-3 py-1 bg-black border border-purple-600`}>
                    {endpoint.method}
                  </span>
                  <code className="font-mono text-purple-400">{endpoint.endpoint}</code>
                </div>
                <p className="text-sm opacity-70 ml-20">{endpoint.description}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Rate Limits Info */}
        <div className="mt-8 terminal-border bg-yellow-900/20 backdrop-blur p-6">
          <h3 className="text-xl font-bold mb-4 text-yellow-400">[!] RATE LIMITS</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
            <div>
              <div className="font-bold mb-1">FREE TIER</div>
              <div className="opacity-70">100 requests/hour</div>
            </div>
            <div>
              <div className="font-bold mb-1">INDIE/PRO TIER</div>
              <div className="opacity-70">1,000 requests/hour</div>
            </div>
            <div>
              <div className="font-bold mb-1">ENTERPRISE TIER</div>
              <div className="opacity-70">Custom limits</div>
            </div>
          </div>
        </div>
      </div>

      {/* Create Key Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/90 backdrop-blur flex items-center justify-center z-50 p-4">
          <div className="terminal-border-strong bg-black p-8 max-w-md w-full">
            <h2 className="text-3xl font-bold mb-6 glow-header">[CREATE API KEY]</h2>

            <div className="mb-6">
              <label className="block text-sm opacity-50 mb-2">KEY NAME</label>
              <input
                type="text"
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
                placeholder="e.g., Production API"
                className="w-full bg-black border-2 border-purple-600 px-4 py-3 font-mono focus:outline-none focus:border-purple-400"
              />
            </div>

            <div className="mb-6 terminal-border bg-yellow-900/20 p-4">
              <div className="text-yellow-400 font-bold mb-2">[!] SECURITY WARNING</div>
              <div className="text-xs opacity-70">
                Make sure to copy your API key now. You won't be able to see it again!
                Store it securely and never commit it to version control.
              </div>
            </div>

            <div className="flex gap-4">
              <button
                onClick={handleCreateKey}
                disabled={!newKeyName || actionLoading === 'create'}
                className="flex-1 py-3 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold disabled:opacity-50 disabled:cursor-not-allowed transition-all"
              >
                {actionLoading === 'create' ? '[CREATING...]' : '[CREATE]'}
              </button>
              <button
                onClick={() => {
                  setShowCreateModal(false);
                  setNewKeyName('');
                }}
                className="flex-1 py-3 bg-red-600 hover:bg-red-500 border-2 border-red-400 font-bold transition-all"
              >
                [CANCEL]
              </button>
            </div>
          </div>
        </div>
      )}

      {/* New Key Generated Modal */}
      {showKeyModal && (
        <div className="fixed inset-0 bg-black/90 backdrop-blur flex items-center justify-center z-50 p-4">
          <div className="terminal-border-strong bg-black p-8 max-w-md w-full">
            <h2 className="text-3xl font-bold mb-6 glow-header text-green-400">[OK KEY CREATED]</h2>

            <div className="mb-6">
              <div className="text-sm opacity-50 mb-2">YOUR NEW API KEY</div>
              <div className="bg-black border-2 border-green-600 px-4 py-3 font-mono text-green-400 break-all text-sm">
                {generatedKey}
              </div>
            </div>

            <div className="mb-6 terminal-border bg-red-900/20 p-4">
              <div className="text-red-400 font-bold mb-2">[!] COPY THIS NOW</div>
              <div className="text-xs opacity-70">
                This is the only time you'll see this key. Make sure to copy it to a secure location.
              </div>
            </div>

            <div className="flex gap-4">
              <button
                onClick={() => {
                  copyToClipboard(generatedKey, 'new-key');
                  setTimeout(() => setShowKeyModal(false), 1500);
                }}
                className="flex-1 py-3 bg-green-600 hover:bg-green-500 border-2 border-green-400 font-bold transition-all"
              >
                {copiedKey === 'new-key' ? '[OK COPIED]' : '[COPY KEY]'}
              </button>
              <button
                onClick={() => setShowKeyModal(false)}
                className="flex-1 py-3 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold transition-all"
              >
                [DONE]
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirmation Modal */}
      {showConfirmModal && (
        <div className="fixed inset-0 bg-black/90 backdrop-blur flex items-center justify-center z-50 p-4">
          <div className="terminal-border-strong bg-black p-8 max-w-md w-full">
            <h2 className="text-3xl font-bold mb-6 glow-header text-yellow-400">
              [{showConfirmModal.type === 'revoke' ? 'REVOKE' : 'REGENERATE'} KEY?]
            </h2>

            <div className="mb-6">
              <div className="text-sm opacity-50 mb-2">KEY NAME</div>
              <div className="text-lg font-bold">{showConfirmModal.keyName}</div>
            </div>

            <div className="mb-6 terminal-border bg-yellow-900/20 p-4">
              <div className="text-yellow-400 font-bold mb-2">[!] WARNING</div>
              <div className="text-xs opacity-70">
                {showConfirmModal.type === 'revoke'
                  ? 'This will permanently delete this API key. Any applications using this key will stop working immediately.'
                  : 'This will generate a new API key. The old key will stop working immediately. Make sure to update your applications with the new key.'}
              </div>
            </div>

            <div className="flex gap-4">
              <button
                onClick={() => {
                  if (showConfirmModal.type === 'revoke') {
                    handleRevokeKey(showConfirmModal.keyId);
                  } else {
                    handleRegenerateKey(showConfirmModal.keyId);
                  }
                }}
                className={`flex-1 py-3 font-bold transition-all ${
                  showConfirmModal.type === 'revoke'
                    ? 'bg-red-600 hover:bg-red-500 border-2 border-red-400'
                    : 'bg-yellow-600 hover:bg-yellow-500 border-2 border-yellow-400'
                }`}
              >
                [{showConfirmModal.type === 'revoke' ? 'REVOKE' : 'REGENERATE'}]
              </button>
              <button
                onClick={() => setShowConfirmModal(null)}
                className="flex-1 py-3 bg-gray-600 hover:bg-gray-500 border-2 border-gray-400 font-bold transition-all"
              >
                [CANCEL]
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
