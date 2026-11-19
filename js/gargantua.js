(() => {
  const motionAllowed = matchMedia('(any-hover: hover) and (any-pointer: fine) and (prefers-reduced-motion: no-preference)');
  const size = 108;
  const radius = size / 2;
  const canvas = document.createElement('canvas');
  const context = canvas.getContext('2d');
  if (!context) return;

  canvas.className = 'gargantua';
  canvas.setAttribute('aria-hidden', 'true');

  function ellipse(x, y, a, b, start = 0, end = Math.PI * 2) {
    context.beginPath();
    context.ellipse(x, y, a, b, 0, start, end);
  }

  function paint() {
    const density = 0.5;
    canvas.width = canvas.height = size * density;
    context.scale(density, density);
    context.translate(radius, radius);
    context.rotate(-0.18);

    const halo = context.createRadialGradient(0, 0, 9, 0, 0, 51);
    halo.addColorStop(0, '#ff7b59a8');
    halo.addColorStop(0.46, '#f64e365c');
    halo.addColorStop(1, '#f62d3000');
    context.fillStyle = halo;
    context.fillRect(-radius, -radius, size, size);

    const fire = context.createLinearGradient(-44, 0, 44, 0);
    fire.addColorStop(0, '#a1182200');
    fire.addColorStop(0.19, '#ed543d');
    fire.addColorStop(0.47, '#ffe1ac');
    fire.addColorStop(0.76, '#ffac71');
    fire.addColorStop(1, '#a1182200');

    // The far side of the disk bends around the shadow above and below.
    context.strokeStyle = fire;
    for (let strand = 0; strand < 10; strand++) {
      context.globalAlpha = 0.72 - strand * 0.05;
      context.lineWidth = 1;
      ellipse(0, 1, 18 + strand * 0.58, 20 + strand * 0.75, Math.PI, 2 * Math.PI);
      context.stroke();
      ellipse(0, -1, 17 + strand * 0.43, 17 + strand * 0.55, 0, Math.PI);
      context.stroke();
    }

    context.globalAlpha = 1;
    context.fillStyle = '#050307';
    ellipse(0, 0, 17.1, 17.1);
    context.fill();

    context.shadowColor = '#ff5b32';
    context.shadowBlur = 8 * density;
    for (let strand = 0; strand < 12; strand++) {
      context.globalAlpha = 0.94 - strand * 0.061;
      context.lineWidth = strand < 4 ? 1.3 : 0.7;
      ellipse(0, 1, 26 + strand * 1.85, 3.3 + strand * 0.32, 0, Math.PI);
      context.stroke();
    }
  }

  let currentX = 0;
  let currentY = 0;
  let targetX = 0;
  let targetY = 0;
  let frame = 0;
  let visible = false;

  function follow() {
    frame = 0;
    const dx = targetX - currentX;
    const dy = targetY - currentY;
    const moving = Math.abs(dx) + Math.abs(dy) > 0.25;
    currentX = moving ? currentX + dx * 0.24 : targetX;
    currentY = moving ? currentY + dy * 0.24 : targetY;
    canvas.style.transform = `translate3d(${currentX - radius}px, ${currentY - radius}px, 0)`;
    if (moving) frame = requestAnimationFrame(follow);
  }

  function hide() {
    cancelAnimationFrame(frame);
    frame = 0;
    visible = false;
    canvas.classList.remove('is-visible');
  }

  function move(event) {
    if (!motionAllowed.matches || event.pointerType !== 'mouse') return;

    const offset = 34;
    const gap = 8;
    const horizontal = event.clientX + offset + radius > innerWidth - gap ? -offset : offset;
    const vertical = event.clientY + offset + radius > innerHeight - gap ? -offset : offset;
    targetX = event.clientX + horizontal;
    targetY = event.clientY + vertical;
    if (!visible) {
      currentX = targetX;
      currentY = targetY;
      visible = true;
      canvas.classList.add('is-visible');
    }
    if (!frame) frame = requestAnimationFrame(follow);
  }

  function setMotionPreference() {
    if (motionAllowed.matches) {
      paint();
      document.body.append(canvas);
    } else {
      hide();
      canvas.remove();
    }
  }

  setMotionPreference();
  motionAllowed.addEventListener('change', setMotionPreference);
  window.addEventListener('pointermove', move, { passive: true });
  document.documentElement.addEventListener('pointerleave', hide);
  window.addEventListener('blur', hide);
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) hide();
  });
})();
