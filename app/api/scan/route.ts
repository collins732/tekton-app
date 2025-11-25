import { NextRequest, NextResponse } from 'next/server';
import { nanoid } from 'nanoid';
import { executeScan } from '@/app/lib/scanner';
import { getAllScans, getUser, deductTokens } from '@/app/lib/db';
import { getUserFromSession } from '@/app/lib/auth';

/**
 * POST /api/scan
 * Démarre un nouveau scan
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { url, cost = 40 } = body;

    // Get authenticated user
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json(
        { error: 'Unauthorized. Please login first.' },
        { status: 401 }
      );
    }

    const user = getUser(userId) as any;

    if (!user) {
      return NextResponse.json(
        { error: 'User not found. Please create default user first.' },
        { status: 404 }
      );
    }

    // Validation de l'URL
    if (!url) {
      return NextResponse.json(
        { error: 'URL is required' },
        { status: 400 }
      );
    }

    // Vérifier que c'est une URL valide
    try {
      new URL(url);
    } catch {
      return NextResponse.json(
        { error: 'Invalid URL format' },
        { status: 400 }
      );
    }

    // Check if user has enough tokens
    if (user.tokens < cost) {
      return NextResponse.json(
        { error: 'Insufficient tokens', required: cost, available: user.tokens },
        { status: 402 }
      );
    }

    // Deduct tokens
    const success = deductTokens(userId, cost);
    if (!success) {
      return NextResponse.json(
        { error: 'Failed to deduct tokens' },
        { status: 500 }
      );
    }

    // Générer un ID unique pour le scan
    const scanId = nanoid(10);

    // Lancer le scan en arrière-plan (non-bloquant)
    executeScan(scanId, url, userId, cost).catch(console.error);

    // Retourner immédiatement l'ID du scan
    return NextResponse.json({
      scanId,
      status: 'pending',
      message: 'Scan started successfully',
      tokensRemaining: user.tokens - cost
    });

  } catch (error) {
    console.error('Error starting scan:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * GET /api/scan
 * Récupère la liste de tous les scans
 */
export async function GET() {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json(
        { error: 'Unauthorized. Please login first.' },
        { status: 401 }
      );
    }

    const scans = getAllScans(userId);

    // Transform to consistent format for frontend
    const formattedScans = scans.map((scan: any) => ({
      scan_id: scan.scanId,
      target: scan.target,
      status: scan.status,
      started_at: scan.startedAt instanceof Date ? scan.startedAt.getTime() : scan.startedAt,
      completed_at: scan.completedAt instanceof Date ? scan.completedAt.getTime() : scan.completedAt,
      progress: scan.progress,
      current_step: scan.currentStep,
      results: scan.results,
      error: scan.error,
      cost: scan.cost || 0
    }));

    return NextResponse.json(formattedScans);
  } catch (error) {
    console.error('Error fetching scans:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
