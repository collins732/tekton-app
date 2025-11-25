'use client';

import { useState, useEffect, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';

interface GitHubConfig {
  login: string;
  name: string;
  avatar_url: string;
  html_url: string;
  public_repos: number;
  followers: number;
  following: number;
  selected_repos: string[];
}

interface GitHubRepo {
  id: number;
  name: string;
  full_name: string;
  description: string | null;
  html_url: string;
  private: boolean;
  language: string | null;
  stargazers_count: number;
  forks_count: number;
  updated_at: string;
  default_branch: string;
}

interface Integration {
  integration_id: string;
  service: string;
  config: GitHubConfig;
  status: string;
  created_at: number;
}

function IntegrationsContent() {
  const searchParams = useSearchParams();
  const [githubIntegration, setGithubIntegration] = useState<Integration | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  // Repos state
  const [repos, setRepos] = useState<GitHubRepo[]>([]);
  const [selectedRepos, setSelectedRepos] = useState<string[]>([]);
  const [showReposModal, setShowReposModal] = useState(false);
  const [reposLoading, setReposLoading] = useState(false);
  const [repoFilter, setRepoFilter] = useState('');

  // Check for success/error params
  useEffect(() => {
    const success = searchParams.get('success');
    const error = searchParams.get('error');

    if (success === 'github_connected') {
      // Reload data after successful connection
      loadData();
    }

    if (error) {
      alert(`GitHub connection error: ${error}`);
    }
  }, [searchParams]);

  // Load data on mount
  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const response = await fetch('/api/integrations');
      if (response.ok) {
        const data = await response.json();
        const github = data.integrations?.find((i: any) => i.service === 'github');
        if (github) {
          // Parse config if string
          if (typeof github.config === 'string') {
            github.config = JSON.parse(github.config);
          }
          setGithubIntegration(github);
          setSelectedRepos(github.config.selected_repos || []);
        } else {
          setGithubIntegration(null);
        }
      }
    } catch (error) {
      console.error('Failed to load integrations:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleConnectGitHub = () => {
    // Redirect to GitHub OAuth
    window.location.href = '/api/github/auth';
  };

  const handleDisconnectGitHub = async () => {
    if (!confirm('Are you sure you want to disconnect GitHub?')) return;

    setActionLoading('disconnect');
    try {
      const response = await fetch('/api/github/disconnect', { method: 'POST' });
      if (response.ok) {
        setGithubIntegration(null);
        setSelectedRepos([]);
        setRepos([]);
      } else {
        alert('Failed to disconnect GitHub');
      }
    } catch (error) {
      console.error('Failed to disconnect:', error);
    } finally {
      setActionLoading(null);
    }
  };

  const handleOpenRepos = async () => {
    setShowReposModal(true);
    setReposLoading(true);

    try {
      const response = await fetch('/api/github/repos');
      if (response.ok) {
        const data = await response.json();
        setRepos(data.repos || []);
        setSelectedRepos(data.selected_repos || []);
      } else {
        alert('Failed to load repositories');
      }
    } catch (error) {
      console.error('Failed to load repos:', error);
    } finally {
      setReposLoading(false);
    }
  };

  const handleToggleRepo = (fullName: string) => {
    setSelectedRepos(prev =>
      prev.includes(fullName)
        ? prev.filter(r => r !== fullName)
        : [...prev, fullName]
    );
  };

  const handleSaveRepos = async () => {
    setActionLoading('save-repos');
    try {
      const response = await fetch('/api/github/repos', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ selected_repos: selectedRepos })
      });

      if (response.ok) {
        setShowReposModal(false);
        loadData(); // Reload to get updated config
      } else {
        alert('Failed to save repositories');
      }
    } catch (error) {
      console.error('Failed to save repos:', error);
    } finally {
      setActionLoading(null);
    }
  };

  const filteredRepos = repos.filter(repo =>
    repo.name.toLowerCase().includes(repoFilter.toLowerCase()) ||
    repo.full_name.toLowerCase().includes(repoFilter.toLowerCase())
  );

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric'
    });
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="terminal-border bg-black/90 backdrop-blur p-8 text-center">
          <div className="text-purple-400 text-4xl mb-4 animate-pulse">[*]</div>
          <div className="text-lg glow-purple">LOADING...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen p-8">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-5xl font-bold mb-4 glow-title">[GITHUB INTEGRATION]</h1>
          <p className="text-xl opacity-70 mb-2">Connect your GitHub account to TEKTON</p>
          <p className="text-sm opacity-50">Automatically create issues when vulnerabilities are found</p>
        </div>

        {/* GitHub Connection Card */}
        <div className="terminal-border bg-black/80 backdrop-blur mb-8">
          {githubIntegration ? (
            // Connected State
            <div className="p-8">
              {/* Profile Header */}
              <div className="flex items-center justify-between mb-8">
                <div className="flex items-center gap-6">
                  <img
                    src={githubIntegration.config.avatar_url}
                    alt={githubIntegration.config.login}
                    className="w-24 h-24 rounded-full border-4 border-purple-600"
                  />
                  <div>
                    <h2 className="text-3xl font-bold glow-purple">{githubIntegration.config.name || githubIntegration.config.login}</h2>
                    <a
                      href={githubIntegration.config.html_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-purple-400 hover:text-purple-300 transition-colors"
                    >
                      @{githubIntegration.config.login}
                    </a>
                    <div className="flex items-center gap-2 mt-2">
                      <span className="text-xs px-3 py-1 bg-green-600 border border-green-400 font-bold">
                        CONNECTED
                      </span>
                    </div>
                  </div>
                </div>
                <button
                  onClick={handleDisconnectGitHub}
                  disabled={actionLoading === 'disconnect'}
                  className="px-4 py-2 bg-red-600 hover:bg-red-500 border-2 border-red-400 font-bold transition-all disabled:opacity-50"
                >
                  {actionLoading === 'disconnect' ? '[...]' : '[DISCONNECT]'}
                </button>
              </div>

              {/* Stats */}
              <div className="grid grid-cols-3 gap-6 mb-8">
                <div className="terminal-border bg-purple-900/20 p-4 text-center">
                  <div className="text-3xl font-bold text-purple-400">{githubIntegration.config.public_repos}</div>
                  <div className="text-xs opacity-50">PUBLIC REPOS</div>
                </div>
                <div className="terminal-border bg-purple-900/20 p-4 text-center">
                  <div className="text-3xl font-bold text-purple-400">{githubIntegration.config.followers}</div>
                  <div className="text-xs opacity-50">FOLLOWERS</div>
                </div>
                <div className="terminal-border bg-purple-900/20 p-4 text-center">
                  <div className="text-3xl font-bold text-purple-400">{githubIntegration.config.following}</div>
                  <div className="text-xs opacity-50">FOLLOWING</div>
                </div>
              </div>

              {/* Selected Repos Section */}
              <div className="terminal-border bg-black/50 p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-xl font-bold glow-accent">SELECTED REPOSITORIES</h3>
                  <button
                    onClick={handleOpenRepos}
                    className="px-4 py-2 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold transition-all"
                  >
                    [SELECT REPOS]
                  </button>
                </div>

                {selectedRepos.length === 0 ? (
                  <div className="text-center py-8 opacity-50">
                    <div className="text-4xl mb-4">[#]</div>
                    <div>No repositories selected yet.</div>
                    <div className="text-sm mt-2">Click "SELECT REPOS" to choose which repos to monitor.</div>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {selectedRepos.map((repoName) => (
                      <div
                        key={repoName}
                        className="flex items-center justify-between p-3 bg-purple-900/20 border border-purple-600"
                      >
                        <div className="flex items-center gap-3">
                          <span className="text-purple-400">[R]</span>
                          <span className="font-mono">{repoName}</span>
                        </div>
                        <a
                          href={`https://github.com/${repoName}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs text-purple-400 hover:text-purple-300"
                        >
                          [VIEW]
                        </a>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ) : (
            // Not Connected State
            <div className="p-8 text-center">
              <div className="text-6xl mb-6">[G]</div>
              <h2 className="text-2xl font-bold mb-4 glow-purple">GitHub</h2>
              <p className="text-lg opacity-70 mb-6">
                Connect your GitHub account to automatically create issues<br />
                when vulnerabilities are found in your scans.
              </p>

              <div className="terminal-border bg-purple-900/20 p-6 mb-8 text-left max-w-md mx-auto">
                <h3 className="text-lg font-bold mb-4 text-purple-400">FEATURES:</h3>
                <ul className="space-y-2 text-sm">
                  <li className="flex items-center gap-2">
                    <span className="text-green-400">[+]</span>
                    <span>View your GitHub profile</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-green-400">[+]</span>
                    <span>Select repositories to monitor</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-green-400">[+]</span>
                    <span>Auto-create issues for vulnerabilities</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-green-400">[+]</span>
                    <span>Link scan results to your repos</span>
                  </li>
                </ul>
              </div>

              <button
                onClick={handleConnectGitHub}
                className="px-8 py-4 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold text-xl transition-all"
              >
                [CONNECT GITHUB]
              </button>
            </div>
          )}
        </div>

        {/* How it works */}
        <div className="terminal-border bg-black/80 backdrop-blur p-6">
          <h3 className="text-xl font-bold mb-4 glow-header">HOW IT WORKS</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="text-center">
              <div className="text-3xl mb-2 text-purple-400">1.</div>
              <div className="font-bold mb-1">CONNECT</div>
              <div className="text-sm opacity-70">Authorize TEKTON to access your GitHub</div>
            </div>
            <div className="text-center">
              <div className="text-3xl mb-2 text-purple-400">2.</div>
              <div className="font-bold mb-1">SELECT</div>
              <div className="text-sm opacity-70">Choose which repos to monitor</div>
            </div>
            <div className="text-center">
              <div className="text-3xl mb-2 text-purple-400">3.</div>
              <div className="font-bold mb-1">SCAN</div>
              <div className="text-sm opacity-70">Issues are created automatically</div>
            </div>
          </div>
        </div>
      </div>

      {/* Select Repos Modal */}
      {showReposModal && (
        <div className="fixed inset-0 bg-black/90 backdrop-blur flex items-center justify-center z-50 p-4">
          <div className="terminal-border-strong bg-black p-8 max-w-3xl w-full max-h-[90vh] overflow-hidden flex flex-col">
            <h2 className="text-3xl font-bold mb-6 glow-header">[SELECT REPOSITORIES]</h2>

            {/* Search */}
            <div className="mb-4">
              <input
                type="text"
                value={repoFilter}
                onChange={(e) => setRepoFilter(e.target.value)}
                placeholder="Search repositories..."
                className="w-full bg-black border-2 border-purple-600 px-4 py-3 font-mono focus:outline-none focus:border-purple-400"
              />
            </div>

            {/* Selected count */}
            <div className="mb-4 text-sm">
              <span className="text-purple-400 font-bold">{selectedRepos.length}</span>
              <span className="opacity-50"> repositories selected</span>
            </div>

            {/* Repos List */}
            <div className="flex-1 overflow-y-auto mb-6 space-y-2">
              {reposLoading ? (
                <div className="text-center py-12">
                  <div className="text-purple-400 text-4xl mb-4 animate-pulse">[*]</div>
                  <div>Loading repositories...</div>
                </div>
              ) : filteredRepos.length === 0 ? (
                <div className="text-center py-12 opacity-50">
                  <div>No repositories found</div>
                </div>
              ) : (
                filteredRepos.map((repo) => (
                  <div
                    key={repo.id}
                    onClick={() => handleToggleRepo(repo.full_name)}
                    className={`p-4 cursor-pointer transition-all border-2 ${
                      selectedRepos.includes(repo.full_name)
                        ? 'bg-purple-900/30 border-purple-400'
                        : 'bg-black/50 border-purple-600 hover:border-purple-400'
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-1">
                          <span className={`text-lg ${selectedRepos.includes(repo.full_name) ? 'text-green-400' : 'text-gray-500'}`}>
                            {selectedRepos.includes(repo.full_name) ? '[✓]' : '[ ]'}
                          </span>
                          <span className="font-bold glow-accent">{repo.name}</span>
                          {repo.private && (
                            <span className="text-xs px-2 py-0.5 bg-yellow-600 border border-yellow-400">
                              PRIVATE
                            </span>
                          )}
                        </div>
                        <div className="text-xs opacity-50 ml-8">{repo.full_name}</div>
                        {repo.description && (
                          <div className="text-sm opacity-70 ml-8 mt-1">{repo.description}</div>
                        )}
                      </div>
                      <div className="text-right text-xs opacity-50">
                        <div className="flex items-center gap-4 mb-1">
                          {repo.language && (
                            <span className="text-purple-400">{repo.language}</span>
                          )}
                          <span>* {repo.stargazers_count}</span>
                        </div>
                        <div>Updated {formatDate(repo.updated_at)}</div>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>

            {/* Actions */}
            <div className="flex gap-4">
              <button
                onClick={handleSaveRepos}
                disabled={actionLoading === 'save-repos'}
                className="flex-1 py-3 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold transition-all disabled:opacity-50"
              >
                {actionLoading === 'save-repos' ? '[SAVING...]' : `[SAVE ${selectedRepos.length} REPOS]`}
              </button>
              <button
                onClick={() => setShowReposModal(false)}
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

export default function IntegrationsPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen flex items-center justify-center">
        <div className="terminal-border bg-black/90 backdrop-blur p-8 text-center">
          <div className="text-purple-400 text-4xl mb-4 animate-pulse">[*]</div>
          <div className="text-lg glow-purple">LOADING...</div>
        </div>
      </div>
    }>
      <IntegrationsContent />
    </Suspense>
  );
}
