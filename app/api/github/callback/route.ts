import { NextRequest, NextResponse } from 'next/server';
import { createIntegration, getIntegrations, deleteIntegration } from '@/app/lib/db';

const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID || '';
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET || '';
const APP_URL = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';

/**
 * GET /api/github/callback
 * Handle GitHub OAuth callback
 */
export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const code = searchParams.get('code');
    const state = searchParams.get('state');
    const error = searchParams.get('error');

    if (error) {
      return NextResponse.redirect(`${APP_URL}/integrations?error=${encodeURIComponent(error)}`);
    }

    if (!code || !state) {
      return NextResponse.redirect(`${APP_URL}/integrations?error=missing_params`);
    }

    // Decode state to get user ID
    let userId: string;
    try {
      const stateData = JSON.parse(Buffer.from(state, 'base64').toString());
      userId = stateData.userId;
    } catch {
      return NextResponse.redirect(`${APP_URL}/integrations?error=invalid_state`);
    }

    // Exchange code for access token
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: `${APP_URL}/api/github/callback`
      })
    });

    const tokenData = await tokenResponse.json();

    if (tokenData.error) {
      console.error('GitHub token error:', tokenData);
      return NextResponse.redirect(`${APP_URL}/integrations?error=${encodeURIComponent(tokenData.error_description || tokenData.error)}`);
    }

    const accessToken = tokenData.access_token;

    // Fetch GitHub user profile
    const userResponse = await fetch('https://api.github.com/user', {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/vnd.github.v3+json'
      }
    });

    const githubUser = await userResponse.json();

    // Remove existing GitHub integration if any
    const existingIntegrations = getIntegrations(userId) as any[];
    const existingGithub = existingIntegrations.find(i => i.service === 'github');
    if (existingGithub) {
      deleteIntegration(existingGithub.integration_id, userId);
    }

    // Save integration with GitHub data
    createIntegration(userId, 'github', {
      access_token: accessToken,
      github_id: githubUser.id,
      login: githubUser.login,
      name: githubUser.name,
      avatar_url: githubUser.avatar_url,
      html_url: githubUser.html_url,
      public_repos: githubUser.public_repos,
      followers: githubUser.followers,
      following: githubUser.following,
      selected_repos: [] // Will be filled when user selects repos
    });

    return NextResponse.redirect(`${APP_URL}/integrations?success=github_connected`);
  } catch (error) {
    console.error('GitHub callback error:', error);
    return NextResponse.redirect(`${APP_URL}/integrations?error=callback_failed`);
  }
}
