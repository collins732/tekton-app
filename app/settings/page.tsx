'use client';

import { useState, useEffect } from 'react';

export default function SettingsPage() {
  const [activeSection, setActiveSection] = useState<'profile' | 'account' | 'notifications' | 'security' | 'billing'>('profile');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error', text: string } | null>(null);

  // Profile state
  const [profile, setProfile] = useState({
    avatar: '🥷',
    username: 'collins_dev',
    bio: 'Cybersecurity enthusiast | JUNIA student | Bug bounty hunter',
    country: 'France',
    github: '',
    twitter: ''
  });

  // Account state
  const [account, setAccount] = useState({
    email: 'collins@tekton.io',
    language: 'English',
    timezone: 'UTC+1 (Paris)'
  });

  // Notifications state
  const [notifications, setNotifications] = useState({
    scan_complete: true,
    vuln_found: true,
    weekly_report: true,
    achievement: true,
    rank_change: true
  });

  // Security state
  const [security, setSecurity] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
    twoFactorEnabled: false
  });

  // Load initial data
  useEffect(() => {
    loadUserData();
  }, []);

  const loadUserData = async () => {
    try {
      // Load user profile
      const userRes = await fetch('/api/user');
      if (userRes.ok) {
        const userData = await userRes.json();
        setProfile({
          avatar: userData.avatar || '🥷',
          username: userData.username || 'collins_dev',
          bio: userData.bio || '',
          country: userData.country || 'France',
          github: userData.github || '',
          twitter: userData.twitter || ''
        });
      }

      // Load account settings
      const accountRes = await fetch('/api/account');
      if (accountRes.ok) {
        const accountData = await accountRes.json();
        setAccount({
          email: accountData.email || '',
          language: accountData.language || 'English',
          timezone: accountData.timezone || 'UTC+1 (Paris)'
        });
      }

      // Load notifications settings
      const settingsRes = await fetch('/api/settings');
      if (settingsRes.ok) {
        const settingsData = await settingsRes.json();
        if (settingsData.notifications) {
          setNotifications({
            scan_complete: !!settingsData.notifications.scan_complete,
            vuln_found: !!settingsData.notifications.vuln_found,
            weekly_report: !!settingsData.notifications.weekly_report,
            achievement: !!settingsData.notifications.achievement,
            rank_change: !!settingsData.notifications.rank_change
          });
        }
      }

      // Load security settings
      const securityRes = await fetch('/api/security');
      if (securityRes.ok) {
        const securityData = await securityRes.json();
        setSecurity(prev => ({
          ...prev,
          twoFactorEnabled: securityData.two_factor_enabled || false
        }));
      }
    } catch (error) {
      console.error('Error loading user data:', error);
    }
  };

  const showMessage = (type: 'success' | 'error', text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 5000);
  };

  // Save Profile
  const saveProfile = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/profile', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(profile)
      });

      const data = await response.json();

      if (response.ok) {
        showMessage('success', 'Profile updated successfully!');
      } else {
        showMessage('error', data.error || 'Failed to update profile');
      }
    } catch (error) {
      showMessage('error', 'Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Save Account
  const saveAccount = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/account', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(account)
      });

      const data = await response.json();

      if (response.ok) {
        showMessage('success', 'Account settings updated successfully!');
        // Reload account data to confirm changes
        const accountRes = await fetch('/api/account');
        if (accountRes.ok) {
          const accountData = await accountRes.json();
          setAccount({
            email: accountData.email || '',
            language: accountData.language || 'English',
            timezone: accountData.timezone || 'UTC+1 (Paris)'
          });
        }
      } else {
        showMessage('error', data.error || 'Failed to update account');
      }
    } catch (error) {
      showMessage('error', 'Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Save Notifications
  const saveNotifications = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/settings', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          notifications: {
            scan_complete: notifications.scan_complete ? 1 : 0,
            vuln_found: notifications.vuln_found ? 1 : 0,
            weekly_report: notifications.weekly_report ? 1 : 0,
            achievement: notifications.achievement ? 1 : 0,
            rank_change: notifications.rank_change ? 1 : 0
          }
        })
      });

      const data = await response.json();

      if (response.ok) {
        showMessage('success', 'Notification settings updated successfully!');
      } else {
        showMessage('error', data.error || 'Failed to update notifications');
      }
    } catch (error) {
      showMessage('error', 'Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Change Password
  const changePassword = async () => {
    if (!security.currentPassword || !security.newPassword) {
      showMessage('error', 'Please fill in all password fields');
      return;
    }

    if (security.newPassword !== security.confirmPassword) {
      showMessage('error', 'New passwords do not match');
      return;
    }

    if (security.newPassword.length < 8) {
      showMessage('error', 'Password must be at least 8 characters');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch('/api/security', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'change_password',
          current_password: security.currentPassword,
          new_password: security.newPassword
        })
      });

      const data = await response.json();

      if (response.ok) {
        showMessage('success', 'Password changed successfully!');
        setSecurity(prev => ({
          ...prev,
          currentPassword: '',
          newPassword: '',
          confirmPassword: ''
        }));
      } else {
        showMessage('error', data.error || 'Failed to change password');
      }
    } catch (error) {
      showMessage('error', 'Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Toggle 2FA
  const toggle2FA = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/security', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'toggle_2fa',
          enable_2fa: !security.twoFactorEnabled
        })
      });

      const data = await response.json();

      if (response.ok) {
        setSecurity(prev => ({ ...prev, twoFactorEnabled: !prev.twoFactorEnabled }));
        showMessage('success', data.message || '2FA updated successfully!');
        if (data.secret) {
          alert(`Your 2FA secret: ${data.secret}\n\nSave this in your authenticator app!`);
        }
      } else {
        showMessage('error', data.error || 'Failed to toggle 2FA');
      }
    } catch (error) {
      showMessage('error', 'Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen p-8">
      <div className="max-w-7xl mx-auto">
        <h1 className="text-5xl font-bold mb-8 glow-title">[SETTINGS]</h1>

        {/* Success/Error Message */}
        {message && (
          <div className={`mb-6 p-4 terminal-border ${
            message.type === 'success' ? 'bg-green-900/20 border-green-600' : 'bg-red-900/20 border-red-600'
          }`}>
            <div className={`font-bold ${message.type === 'success' ? 'text-green-400' : 'text-red-400'}`}>
              {message.type === 'success' ? '✓ ' : '✗ '}
              {message.text}
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          {/* Sidebar */}
          <div className="terminal-border bg-black/80 backdrop-blur p-6 h-fit">
            <nav className="space-y-2">
              {[
                { id: 'profile', label: 'Profile', icon: '👤' },
                { id: 'account', label: 'Account', icon: '⚙️' },
                { id: 'notifications', label: 'Notifications', icon: '🔔' },
                { id: 'security', label: 'Security', icon: '🔒' },
                { id: 'billing', label: 'Billing', icon: '💳' }
              ].map((item) => (
                <button
                  key={item.id}
                  onClick={() => setActiveSection(item.id as any)}
                  className={`w-full text-left px-4 py-3 font-bold transition-all flex items-center gap-3 ${
                    activeSection === item.id
                      ? 'bg-purple-600 border-2 border-purple-400'
                      : 'border-2 border-transparent hover:bg-purple-900/20'
                  }`}
                >
                  <span>{item.icon}</span>
                  {item.label}
                </button>
              ))}
            </nav>
          </div>

          {/* Content */}
          <div className="lg:col-span-3">
            {/* PROFILE SECTION */}
            {activeSection === 'profile' && (
              <div className="terminal-border bg-black/80 backdrop-blur p-8">
                <h2 className="text-3xl font-bold mb-6 glow-header">PROFILE SETTINGS</h2>

                <div className="space-y-6">
                  <div>
                    <label className="block text-sm opacity-50 mb-2">AVATAR</label>
                    <div className="flex items-center gap-4">
                      <div className="text-6xl">{profile.avatar}</div>
                      <select
                        value={profile.avatar}
                        onChange={(e) => setProfile({ ...profile, avatar: e.target.value })}
                        className="bg-black border-2 border-purple-600 px-4 py-2 font-mono focus:outline-none focus:border-purple-400"
                      >
                        <option value="🥷">🥷 Ninja</option>
                        <option value="👨‍💻">👨‍💻 Developer</option>
                        <option value="🦸">🦸 Superhero</option>
                        <option value="🤖">🤖 Robot</option>
                        <option value="👽">👽 Alien</option>
                        <option value="🐱‍💻">🐱‍💻 Hacker Cat</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm opacity-50 mb-2">USERNAME</label>
                    <input
                      type="text"
                      value={profile.username}
                      onChange={(e) => setProfile({ ...profile, username: e.target.value })}
                      className="w-full bg-black border-2 border-purple-600 px-4 py-3 font-mono focus:outline-none focus:border-purple-400"
                    />
                  </div>

                  <div>
                    <label className="block text-sm opacity-50 mb-2">BIO</label>
                    <textarea
                      value={profile.bio}
                      onChange={(e) => setProfile({ ...profile, bio: e.target.value })}
                      className="w-full bg-black border-2 border-purple-600 px-4 py-3 font-mono focus:outline-none focus:border-purple-400 h-24"
                    />
                  </div>

                  <div>
                    <label className="block text-sm opacity-50 mb-2">COUNTRY</label>
                    <select
                      value={profile.country}
                      onChange={(e) => setProfile({ ...profile, country: e.target.value })}
                      className="w-full bg-black border-2 border-purple-600 px-4 py-3 font-mono focus:outline-none focus:border-purple-400"
                    >
                      <option>France</option>
                      <option>United States</option>
                      <option>United Kingdom</option>
                      <option>Germany</option>
                      <option>Canada</option>
                      <option>Japan</option>
                      <option>Australia</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm opacity-50 mb-2">GITHUB</label>
                    <input
                      type="text"
                      value={profile.github}
                      onChange={(e) => setProfile({ ...profile, github: e.target.value })}
                      placeholder="github.com/username"
                      className="w-full bg-black border-2 border-purple-600 px-4 py-3 font-mono focus:outline-none focus:border-purple-400"
                    />
                  </div>

                  <div>
                    <label className="block text-sm opacity-50 mb-2">TWITTER</label>
                    <input
                      type="text"
                      value={profile.twitter}
                      onChange={(e) => setProfile({ ...profile, twitter: e.target.value })}
                      placeholder="@username"
                      className="w-full bg-black border-2 border-purple-600 px-4 py-3 font-mono focus:outline-none focus:border-purple-400"
                    />
                  </div>

                  <button
                    onClick={saveProfile}
                    disabled={loading}
                    className="w-full py-3 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {loading ? '[SAVING...]' : '[SAVE CHANGES]'}
                  </button>
                </div>
              </div>
            )}

            {/* ACCOUNT SECTION */}
            {activeSection === 'account' && (
              <div className="terminal-border bg-black/80 backdrop-blur p-8">
                <h2 className="text-3xl font-bold mb-6 glow-header">ACCOUNT SETTINGS</h2>

                <div className="space-y-6">
                  <div>
                    <label className="block text-sm opacity-50 mb-2">EMAIL</label>
                    <input
                      type="email"
                      value={account.email}
                      onChange={(e) => setAccount({ ...account, email: e.target.value })}
                      className="w-full bg-black border-2 border-purple-600 px-4 py-3 font-mono focus:outline-none focus:border-purple-400"
                    />
                  </div>

                  <div>
                    <label className="block text-sm opacity-50 mb-2">LANGUAGE</label>
                    <select
                      value={account.language}
                      onChange={(e) => setAccount({ ...account, language: e.target.value })}
                      className="w-full bg-black border-2 border-purple-600 px-4 py-3 font-mono focus:outline-none focus:border-purple-400"
                    >
                      <option value="English">English</option>
                      <option value="Français">Français</option>
                      <option value="Español">Español</option>
                      <option value="Deutsch">Deutsch</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm opacity-50 mb-2">TIMEZONE</label>
                    <select
                      value={account.timezone}
                      onChange={(e) => setAccount({ ...account, timezone: e.target.value })}
                      className="w-full bg-black border-2 border-purple-600 px-4 py-3 font-mono focus:outline-none focus:border-purple-400"
                    >
                      <option value="UTC+1 (Paris)">UTC+1 (Paris)</option>
                      <option value="UTC+0 (London)">UTC+0 (London)</option>
                      <option value="UTC-5 (New York)">UTC-5 (New York)</option>
                      <option value="UTC-8 (Los Angeles)">UTC-8 (Los Angeles)</option>
                      <option value="UTC+9 (Tokyo)">UTC+9 (Tokyo)</option>
                    </select>
                  </div>

                  <button
                    onClick={saveAccount}
                    disabled={loading}
                    className="w-full py-3 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold transition-all disabled:opacity-50"
                  >
                    {loading ? '[SAVING...]' : '[SAVE CHANGES]'}
                  </button>

                  <div className="pt-6 border-t border-purple-600">
                    <h3 className="text-xl font-bold text-red-400 mb-3">DANGER ZONE</h3>
                    <p className="text-sm opacity-70 mb-4">Permanently delete your account and all data</p>
                    <button className="px-6 py-3 bg-red-600 hover:bg-red-500 border-2 border-red-400 font-bold transition-all">
                      [DELETE ACCOUNT]
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* NOTIFICATIONS SECTION */}
            {activeSection === 'notifications' && (
              <div className="terminal-border bg-black/80 backdrop-blur p-8">
                <h2 className="text-3xl font-bold mb-6 glow-header">NOTIFICATION SETTINGS</h2>

                <div className="space-y-6">
                  {[
                    { key: 'scan_complete', label: 'Scan Complete', desc: 'Notify when a scan finishes' },
                    { key: 'vuln_found', label: 'Vulnerabilities Found', desc: 'Alert on critical vulnerabilities' },
                    { key: 'weekly_report', label: 'Weekly Report', desc: 'Receive weekly security summary' },
                    { key: 'achievement', label: 'Achievements', desc: 'Notify when you unlock achievements' }
                  ].map((item) => (
                    <div key={item.key} className="flex items-center justify-between p-4 terminal-border bg-purple-900/10">
                      <div>
                        <div className="font-bold text-purple-400">{item.label}</div>
                        <div className="text-sm opacity-70">{item.desc}</div>
                      </div>
                      <button
                        onClick={() => setNotifications({ ...notifications, [item.key]: !notifications[item.key as keyof typeof notifications] })}
                        className={`w-12 h-6 rounded-full transition-all ${
                          notifications[item.key as keyof typeof notifications] ? 'bg-green-600' : 'bg-gray-600'
                        }`}
                      >
                        <div className={`w-5 h-5 rounded-full bg-white transition-transform ${
                          notifications[item.key as keyof typeof notifications] ? 'translate-x-6' : 'translate-x-1'
                        }`} />
                      </button>
                    </div>
                  ))}

                  <button
                    onClick={saveNotifications}
                    disabled={loading}
                    className="w-full py-3 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold transition-all disabled:opacity-50"
                  >
                    {loading ? '[SAVING...]' : '[SAVE CHANGES]'}
                  </button>
                </div>
              </div>
            )}

            {/* SECURITY SECTION */}
            {activeSection === 'security' && (
              <div className="terminal-border bg-black/80 backdrop-blur p-8">
                <h2 className="text-3xl font-bold mb-6 glow-header">SECURITY SETTINGS</h2>

                <div className="space-y-8">
                  {/* Change Password */}
                  <div>
                    <h3 className="text-xl font-bold mb-4 text-purple-400">CHANGE PASSWORD</h3>
                    <div className="space-y-4">
                      <input
                        type="password"
                        placeholder="Current Password"
                        value={security.currentPassword}
                        onChange={(e) => setSecurity({ ...security, currentPassword: e.target.value })}
                        className="w-full bg-black border-2 border-purple-600 px-4 py-3 font-mono focus:outline-none focus:border-purple-400"
                      />
                      <input
                        type="password"
                        placeholder="New Password"
                        value={security.newPassword}
                        onChange={(e) => setSecurity({ ...security, newPassword: e.target.value })}
                        className="w-full bg-black border-2 border-purple-600 px-4 py-3 font-mono focus:outline-none focus:border-purple-400"
                      />
                      <input
                        type="password"
                        placeholder="Confirm New Password"
                        value={security.confirmPassword}
                        onChange={(e) => setSecurity({ ...security, confirmPassword: e.target.value })}
                        className="w-full bg-black border-2 border-purple-600 px-4 py-3 font-mono focus:outline-none focus:border-purple-400"
                      />
                      <button
                        onClick={changePassword}
                        disabled={loading}
                        className="w-full py-3 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold transition-all disabled:opacity-50"
                      >
                        {loading ? '[CHANGING...]' : '[CHANGE PASSWORD]'}
                      </button>
                    </div>
                  </div>

                  {/* 2FA */}
                  <div className="pt-6 border-t border-purple-600">
                    <h3 className="text-xl font-bold mb-4 text-purple-400">TWO-FACTOR AUTHENTICATION</h3>
                    <div className="flex items-center justify-between p-4 terminal-border bg-purple-900/10 mb-4">
                      <div>
                        <div className="font-bold">2FA Status</div>
                        <div className="text-sm opacity-70">
                          {security.twoFactorEnabled ? 'Enabled - Your account is protected' : 'Disabled - Enable for extra security'}
                        </div>
                      </div>
                      <span className={`px-4 py-2 font-bold ${
                        security.twoFactorEnabled ? 'bg-green-600 border-2 border-green-400' : 'bg-gray-600 border-2 border-gray-400'
                      }`}>
                        {security.twoFactorEnabled ? 'ENABLED' : 'DISABLED'}
                      </span>
                    </div>
                    <button
                      onClick={toggle2FA}
                      disabled={loading}
                      className={`w-full py-3 border-2 font-bold transition-all disabled:opacity-50 ${
                        security.twoFactorEnabled
                          ? 'bg-red-600 hover:bg-red-500 border-red-400'
                          : 'bg-green-600 hover:bg-green-500 border-green-400'
                      }`}
                    >
                      {loading ? '[PROCESSING...]' : security.twoFactorEnabled ? '[DISABLE 2FA]' : '[ENABLE 2FA]'}
                    </button>
                  </div>

                  {/* Active Sessions */}
                  <div className="pt-6 border-t border-purple-600">
                    <h3 className="text-xl font-bold mb-4 text-purple-400">ACTIVE SESSIONS</h3>
                    <div className="space-y-3">
                      <div className="p-4 terminal-border bg-green-900/10">
                        <div className="flex items-center justify-between">
                          <div>
                            <div className="font-bold">Chrome on Windows</div>
                            <div className="text-sm opacity-70">Paris, France • Just now</div>
                          </div>
                          <span className="text-green-400 font-bold">CURRENT</span>
                        </div>
                      </div>
                      <div className="p-4 terminal-border bg-purple-900/10">
                        <div className="flex items-center justify-between">
                          <div>
                            <div className="font-bold">Firefox on MacOS</div>
                            <div className="text-sm opacity-70">Lyon, France • 2 days ago</div>
                          </div>
                          <button className="px-4 py-2 bg-red-600 hover:bg-red-500 border-2 border-red-400 font-bold text-sm">
                            [REVOKE]
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* BILLING SECTION */}
            {activeSection === 'billing' && (
              <div className="terminal-border bg-black/80 backdrop-blur p-8">
                <h2 className="text-3xl font-bold mb-6 glow-header">BILLING</h2>

                <div className="space-y-6">
                  {/* Current Plan */}
                  <div className="p-6 terminal-border bg-purple-900/10">
                    <div className="flex items-center justify-between mb-4">
                      <div>
                        <div className="text-sm opacity-50 mb-1">CURRENT PLAN</div>
                        <div className="text-3xl font-bold glow-title">PRO</div>
                      </div>
                      <div className="text-right">
                        <div className="text-3xl font-bold text-green-400">79€</div>
                        <div className="text-sm opacity-50">per month</div>
                      </div>
                    </div>
                    <button className="w-full py-2 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold">
                      [CHANGE PLAN]
                    </button>
                  </div>

                  {/* Payment Method */}
                  <div>
                    <h3 className="text-xl font-bold mb-4 text-purple-400">PAYMENT METHOD</h3>
                    <div className="p-4 terminal-border bg-purple-900/10 flex items-center justify-between">
                      <div>
                        <div className="font-bold">Visa ending in 4242</div>
                        <div className="text-sm opacity-70">Expires 12/2027</div>
                      </div>
                      <button className="px-4 py-2 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold">
                        [UPDATE]
                      </button>
                    </div>
                  </div>

                  {/* Billing History */}
                  <div>
                    <h3 className="text-xl font-bold mb-4 text-purple-400">BILLING HISTORY</h3>
                    <div className="space-y-2">
                      {[
                        { date: 'Mar 1, 2026', amount: '79€', status: 'PAID' },
                        { date: 'Feb 1, 2026', amount: '79€', status: 'PAID' },
                        { date: 'Jan 1, 2026', amount: '79€', status: 'PAID' }
                      ].map((invoice, i) => (
                        <div key={i} className="p-3 terminal-border bg-purple-900/10 flex items-center justify-between">
                          <div className="flex items-center gap-4">
                            <span className="font-mono">{invoice.date}</span>
                            <span className="font-bold">{invoice.amount}</span>
                          </div>
                          <div className="flex items-center gap-3">
                            <span className="text-green-400 font-bold">{invoice.status}</span>
                            <button className="text-purple-400 hover:text-purple-300 text-sm">[DOWNLOAD]</button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
