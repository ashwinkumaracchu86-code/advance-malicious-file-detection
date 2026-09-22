import { useRef, useEffect, useCallback } from 'react';
import { useTheme } from '../../context/ThemeContext';

const STAR_LAYERS = [
  { count: 200, speedFactor: 0.15, sizeRange: [0.3, 0.7], brightnessRange: [0.2, 0.5] },
  { count: 150, speedFactor: 0.3, sizeRange: [0.5, 1.2], brightnessRange: [0.4, 0.7] },
  { count: 80, speedFactor: 0.5, sizeRange: [1.0, 1.8], brightnessRange: [0.6, 0.9] },
  { count: 30, speedFactor: 0.7, sizeRange: [1.5, 2.5], brightnessRange: [0.8, 1.0] },
];

const TWINKLE_SPEED = 0.0008;
const PARALLAX_SENSITIVITY = 0.012;
const CURSOR_INFLUENCE_RADIUS = 150;
const CURSOR_DISPLACEMENT = 0.8;
const RETURN_SPEED = 0.03;
const NEBULA_POINTS = 12;

function isReducedMotionPreferred() {
  if (typeof window === 'undefined') return false;
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

function isMobile() {
  if (typeof window === 'undefined') return false;
  return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent) || window.innerWidth < 768;
}

function getMobileMultiplier() {
  if (typeof window === 'undefined') return 1;
  if (window.innerWidth < 480) return 0.35;
  if (window.innerWidth < 768) return 0.5;
  return 1;
}

function hexToRgb(hex) {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return { r, g, b };
}

const THEMES = {
  dark: {
    background: '#020617',
    starBase: [200, 220, 255],
    starVariance: [55, 35, 0],
    glowColors: [
      { r: 120, g: 140, b: 255 },
      { r: 180, g: 120, b: 255 },
      { r: 100, g: 180, b: 255 },
    ],
    nebulaColors: [
      { r: 30, g: 40, b: 80, a: 0.015 },
      { r: 50, g: 20, b: 80, a: 0.01 },
      { r: 20, g: 50, b: 90, a: 0.012 },
    ],
    cursorGlow: { r: 150, g: 170, b: 255, a: 0.06 },
    nebulaBrightness: 1,
    starBrightnessMultiplier: 1,
  },
  light: {
    background: '#f1f5f9',
    starBase: [100, 120, 160],
    starVariance: [40, 40, 50],
    glowColors: [
      { r: 120, g: 140, b: 200 },
      { r: 140, g: 120, b: 200 },
      { r: 100, g: 150, b: 200 },
    ],
    nebulaColors: [
      { r: 180, g: 190, b: 220, a: 0.008 },
      { r: 200, g: 180, b: 220, a: 0.006 },
      { r: 170, g: 190, b: 230, a: 0.007 },
    ],
    cursorGlow: { r: 120, g: 140, b: 200, a: 0.04 },
    nebulaBrightness: 0.4,
    starBrightnessMultiplier: 0.55,
  },
};

export default function GalaxyBackground() {
  const canvasRef = useRef(null);
  const stateRef = useRef({
    stars: [],
    nebulaBlobs: [],
    mouse: { x: 0, y: 0, active: false },
    targetMouse: { x: 0, y: 0 },
    currentMouse: { x: 0, y: 0 },
    animationId: null,
    lastTime: 0,
    isVisible: true,
    reducedMotion: isReducedMotionPreferred(),
    mobile: isMobile(),
    themeConfig: THEMES.dark,
  });
  const { theme } = useTheme();
  const themeRef = useRef(theme);

  useEffect(() => {
    themeRef.current = theme;
    stateRef.current.themeConfig = THEMES[theme] || THEMES.dark;
  }, [theme]);

  const initStars = useCallback((canvas) => {
    const w = canvas.width;
    const h = canvas.height;
    const state = stateRef.current;
    const multiplier = state.mobile ? getMobileMultiplier() : 1;

    state.stars = [];
    STAR_LAYERS.forEach((layer) => {
      const count = Math.floor(layer.count * multiplier);
      for (let i = 0; i < count; i++) {
        state.stars.push({
          x: Math.random() * w,
          y: Math.random() * h,
          baseX: Math.random() * w,
          baseY: Math.random() * h,
          size: layer.sizeRange[0] + Math.random() * (layer.sizeRange[1] - layer.sizeRange[0]),
          brightness: layer.brightnessRange[0] + Math.random() * (layer.brightnessRange[1] - layer.brightnessRange[0]),
          speedFactor: layer.speedFactor,
          twinkleOffset: Math.random() * Math.PI * 2,
          twinkleSpeed: TWINKLE_SPEED * (0.7 + Math.random() * 0.6),
          displacementX: 0,
          displacementY: 0,
          isGlowing: Math.random() < 0.08,
          glowSize: 3 + Math.random() * 5,
        });
      }
    });
  }, []);

  const initNebula = useCallback((canvas) => {
    const state = stateRef.current;
    const w = canvas.width;
    const h = canvas.height;
    state.nebulaBlobs = [];

    for (let i = 0; i < NEBULA_POINTS; i++) {
      state.nebulaBlobs.push({
        x: Math.random() * w,
        y: Math.random() * h,
        radius: 100 + Math.random() * 250,
        driftX: (Math.random() - 0.5) * 0.15,
        driftY: (Math.random() - 0.5) * 0.1,
        phaseOffset: Math.random() * Math.PI * 2,
      });
    }
  }, []);

  const drawNebula = useCallback((ctx, time) => {
    const state = stateRef.current;
    const tc = state.themeConfig;
    const w = ctx.canvas.width;
    const h = ctx.canvas.height;

    state.nebulaBlobs.forEach((blob) => {
      const breathe = 1 + Math.sin(time * 0.0003 + blob.phaseOffset) * 0.08;
      const r = blob.radius * breathe * tc.nebulaBrightness;
      const cx = blob.x + Math.sin(time * 0.0002 + blob.phaseOffset) * 15;
      const cy = blob.y + Math.cos(time * 0.00015 + blob.phaseOffset) * 10;

      const gradient = ctx.createRadialGradient(cx, cy, 0, cx, cy, r);
      const nebulaColor = tc.nebulaColors[0];
      gradient.addColorStop(0, `rgba(${nebulaColor.r}, ${nebulaColor.g}, ${nebulaColor.b}, ${nebulaColor.a})`);
      gradient.addColorStop(0.5, `rgba(${nebulaColor.r}, ${nebulaColor.g}, ${nebulaColor.b}, ${nebulaColor.a * 0.4})`);
      gradient.addColorStop(1, 'rgba(0, 0, 0, 0)');

      ctx.fillStyle = gradient;
      ctx.fillRect(cx - r, cy - r, r * 2, r * 2);
    });
  }, []);

  const drawStars = useCallback((ctx, time) => {
    const state = stateRef.current;
    const tc = state.themeConfig;
    const w = ctx.canvas.width;
    const h = ctx.canvas.height;
    const mx = state.currentMouse.x;
    const my = state.currentMouse.y;
    const mouseActive = state.mouse.active;
    const reducedMotion = state.reducedMotion;

    state.stars.forEach((star) => {
      const twinkle = reducedMotion ? 0.8 : 0.5 + 0.5 * Math.sin(time * star.twinkleSpeed + star.twinkleOffset);
      const baseAlpha = star.brightness * twinkle * tc.starBrightnessMultiplier;

      let px = star.baseX;
      let py = star.baseY;

      if (!reducedMotion && mouseActive) {
        const dx = (mx - w / 2) * PARALLAX_SENSITIVITY * star.speedFactor;
        const dy = (my - h / 2) * PARALLAX_SENSITIVITY * star.speedFactor;
        px += dx;
        py += dy;

        const sdx = px - mx;
        const sdy = py - my;
        const distToCursor = Math.sqrt(sdx * sdx + sdy * sdy);

        if (distToCursor < CURSOR_INFLUENCE_RADIUS && distToCursor > 0) {
          const influence = 1 - distToCursor / CURSOR_INFLUENCE_RADIUS;
          const influenceSmooth = influence * influence * (3 - 2 * influence);
          const angle = Math.atan2(sdy, sdx);
          const pushX = Math.cos(angle) * CURSOR_DISPLACEMENT * influenceSmooth * 20 * (1 - star.speedFactor * 0.5);
          const pushY = Math.sin(angle) * CURSOR_DISPLACEMENT * influenceSmooth * 20 * (1 - star.speedFactor * 0.5);
          star.displacementX += (pushX - star.displacementX) * 0.08;
          star.displacementY += (pushY - star.displacementY) * 0.08;
        } else {
          star.displacementX += (0 - star.displacementX) * RETURN_SPEED;
          star.displacementY += (0 - star.displacementY) * RETURN_SPEED;
        }
      } else {
        star.displacementX += (0 - star.displacementX) * RETURN_SPEED;
        star.displacementY += (0 - star.displacementY) * RETURN_SPEED;
      }

      px += star.displacementX;
      py += star.displacementY;

      if (px < -10) px += w + 20;
      else if (px > w + 10) px -= w + 20;
      if (py < -10) py += h + 20;
      else if (py > h + 10) py -= h + 20;

      star.x = px;
      star.y = py;

      const r = tc.starBase[0] + (Math.random() - 0.5) * tc.starVariance[0] * 0.1;
      const g = tc.starBase[1] + (Math.random() - 0.5) * tc.starVariance[1] * 0.1;
      const b = tc.starBase[2] + (Math.random() - 0.5) * tc.starVariance[2] * 0.1;

      if (star.isGlowing) {
        const glowGrad = ctx.createRadialGradient(px, py, 0, px, py, star.glowSize * 2);
        const glowColor = tc.glowColors[Math.floor(Math.random() * tc.glowColors.length)];
        glowGrad.addColorStop(0, `rgba(${glowColor.r}, ${glowColor.g}, ${glowColor.b}, ${baseAlpha * 0.3})`);
        glowGrad.addColorStop(1, 'rgba(0, 0, 0, 0)');
        ctx.fillStyle = glowGrad;
        ctx.fillRect(px - star.glowSize * 2, py - star.glowSize * 2, star.glowSize * 4, star.glowSize * 4);
      }

      ctx.beginPath();
      ctx.arc(px, py, star.size, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${Math.round(r)}, ${Math.round(g)}, ${Math.round(b)}, ${baseAlpha})`;
      ctx.fill();
    });
  }, []);

  const drawCursorGlow = useCallback((ctx) => {
    const state = stateRef.current;
    if (!state.mouse.active) return;

    const tc = state.themeConfig;
    const mx = state.currentMouse.x;
    const my = state.currentMouse.y;
    const glow = tc.cursorGlow;

    const grad = ctx.createRadialGradient(mx, my, 0, mx, my, CURSOR_INFLUENCE_RADIUS);
    grad.addColorStop(0, `rgba(${glow.r}, ${glow.g}, ${glow.b}, ${glow.a})`);
    grad.addColorStop(0.4, `rgba(${glow.r}, ${glow.g}, ${glow.b}, ${glow.a * 0.4})`);
    grad.addColorStop(1, 'rgba(0, 0, 0, 0)');
    ctx.fillStyle = grad;
    ctx.fillRect(mx - CURSOR_INFLUENCE_RADIUS, my - CURSOR_INFLUENCE_RADIUS, CURSOR_INFLUENCE_RADIUS * 2, CURSOR_INFLUENCE_RADIUS * 2);
  }, []);

  const animate = useCallback((timestamp) => {
    const state = stateRef.current;
    if (!state.isVisible || !canvasRef.current) {
      state.animationId = requestAnimationFrame(animate);
      return;
    }

    const ctx = canvasRef.current.getContext('2d');
    const w = canvasRef.current.width;
    const h = canvasRef.current.height;
    const tc = state.themeConfig;

    state.currentMouse.x += (state.targetMouse.x - state.currentMouse.x) * 0.06;
    state.currentMouse.y += (state.targetMouse.y - state.currentMouse.y) * 0.06;

    ctx.clearRect(0, 0, w, h);

    drawNebula(ctx, timestamp);
    drawStars(ctx, timestamp);
    drawCursorGlow(ctx);

    state.animationId = requestAnimationFrame(animate);
  }, [drawNebula, drawStars, drawCursorGlow]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const state = stateRef.current;

    const handleResize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = window.innerWidth * dpr;
      canvas.height = window.innerHeight * dpr;
      canvas.style.width = `${window.innerWidth}px`;
      canvas.style.height = `${window.innerHeight}px`;
      const ctx = canvas.getContext('2d');
      ctx.scale(dpr, dpr);
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      state.mobile = isMobile();
      initStars(canvas);
      initNebula(canvas);
    };

    const handleMouseMove = (e) => {
      state.targetMouse.x = e.clientX;
      state.targetMouse.y = e.clientY;
      state.mouse.active = true;
    };

    const handleMouseLeave = () => {
      state.mouse.active = false;
    };

    const handleTouchMove = (e) => {
      if (e.touches.length > 0) {
        state.targetMouse.x = e.touches[0].clientX;
        state.targetMouse.y = e.touches[0].clientY;
        state.mouse.active = true;
      }
    };

    const handleTouchEnd = () => {
      state.mouse.active = false;
    };

    const handleVisibilityChange = () => {
      state.isVisible = !document.hidden;
    };

    const motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    const handleMotionChange = (e) => {
      state.reducedMotion = e.matches;
    };

    state.reducedMotion = motionQuery.matches;
    motionQuery.addEventListener('change', handleMotionChange);

    handleResize();
    window.addEventListener('resize', handleResize);
    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseleave', handleMouseLeave);
    window.addEventListener('touchmove', handleTouchMove, { passive: true });
    window.addEventListener('touchend', handleTouchEnd);
    document.addEventListener('visibilitychange', handleVisibilityChange);

    state.animationId = requestAnimationFrame(animate);

    return () => {
      if (state.animationId) cancelAnimationFrame(state.animationId);
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseleave', handleMouseLeave);
      window.removeEventListener('touchmove', handleTouchMove);
      window.removeEventListener('touchend', handleTouchEnd);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      motionQuery.removeEventListener('change', handleMotionChange);
    };
  }, [animate, initStars, initNebula]);

  return (
    <canvas
      ref={canvasRef}
      className="galaxy-canvas"
      aria-hidden="true"
    />
  );
}
