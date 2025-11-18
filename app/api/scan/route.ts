import { NextRequest, NextResponse } from 'next/server';
import { nanoid } from 'nanoid';
import { executeScan } from '@/app/lib/scanner';
import { getAllScans } from '@/app/lib/db';

/**
 * POST /api/scan
 * Démarre un nouveau scan
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { url } = body;

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

    // Générer un ID unique pour le scan
    const scanId = nanoid(10);

    // Lancer le scan en arrière-plan (non-bloquant)
    executeScan(scanId, url).catch(console.error);

    // Retourner immédiatement l'ID du scan
    return NextResponse.json({
      scanId,
      status: 'pending',
      message: 'Scan started successfully',
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
    const scans = getAllScans();
    return NextResponse.json(scans);
  } catch (error) {
    console.error('Error fetching scans:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
