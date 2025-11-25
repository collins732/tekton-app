import { NextRequest, NextResponse } from 'next/server';
import { getUserFromSession } from '@/app/lib/auth';
import { getIntegrations } from '@/app/lib/db';

/**
 * GET /api/github/repos
 * Fetch user's GitHub repositories
 */
export async function GET() {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    // Get GitHub integration
    const integrations = getIntegrations(userId) as any[];
    const githubIntegration = integrations.find(i => i.service === 'github');

    if (!githubIntegration) {
      return NextResponse.json({ error: 'GitHub not connected' }, { status: 400 });
    }

    const config = typeof githubIntegration.config === 'string'
      ? JSON.parse(githubIntegration.config)
      : githubIntegration.config;

    const accessToken = config.access_token;

    if (!accessToken) {
      return NextResponse.json({ error: 'No access token' }, { status: 400 });
    }

    // Fetch repositories from GitHub
    const response = await fetch('https://api.github.com/user/repos?per_page=100&sort=updated', {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/vnd.github.v3+json'
      }
    });

    if (!response.ok) {
      return NextResponse.json({ error: 'Failed to fetch repos from GitHub' }, { status: 500 });
    }

    const repos = await response.json();

    // Return simplified repo data
    const simplifiedRepos = repos.map((repo: any) => ({
      id: repo.id,
      name: repo.name,
      full_name: repo.full_name,
      description: repo.description,
      html_url: repo.html_url,
      private: repo.private,
      language: repo.language,
      stargazers_count: repo.stargazers_count,
      forks_count: repo.forks_count,
      updated_at: repo.updated_at,
      default_branch: repo.default_branch
    }));

    return NextResponse.json({
      repos: simplifiedRepos,
      selected_repos: config.selected_repos || []
    });
  } catch (error) {
    console.error('Error fetching GitHub repos:', error);
    return NextResponse.json({ error: 'Failed to fetch repositories' }, { status: 500 });
  }
}

/**
 * POST /api/github/repos
 * Save selected repositories
 */
export async function POST(request: NextRequest) {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    const { selected_repos } = await request.json();

    // Get GitHub integration
    const integrations = getIntegrations(userId) as any[];
    const githubIntegration = integrations.find(i => i.service === 'github');

    if (!githubIntegration) {
      return NextResponse.json({ error: 'GitHub not connected' }, { status: 400 });
    }

    const config = typeof githubIntegration.config === 'string'
      ? JSON.parse(githubIntegration.config)
      : githubIntegration.config;

    // Update config with selected repos
    const updatedConfig = {
      ...config,
      selected_repos: selected_repos || []
    };

    // Update in database
    const db = (await import('@/app/lib/db')).default;
    const stmt = db.prepare('UPDATE integrations SET config = ? WHERE integration_id = ?');
    stmt.run(JSON.stringify(updatedConfig), githubIntegration.integration_id);

    return NextResponse.json({
      success: true,
      message: 'Repositories saved successfully'
    });
  } catch (error) {
    console.error('Error saving repos:', error);
    return NextResponse.json({ error: 'Failed to save repositories' }, { status: 500 });
  }
}
