'use client';

import Spline from '@splinetool/react-spline';

export default function SplineViewer() {
  return (
    <div className="w-full h-full bg-transparent relative">
      <Spline
        scene="https://prod.spline.design/akUKTv7FEnibl3uX/scene.splinecode"
        style={{ width: '100%', height: '100%', background: 'transparent' }}
      />
      
      {/* Overlay pour masquer le badge en bas à droite */}
      <div className="absolute bottom-0 right-0 w-70 h-16 bg-gradient-to-tl from-black via-black to-transparent pointer-events-none z-10" />
    </div>
  );
}