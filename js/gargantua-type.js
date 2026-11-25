// Bend the painted glyphs in place. Layout, selectable text and link hitboxes
// continue to belong to the original DOM; only nearby visible runs get a filter.
export function createTextLens(scene) {
  const ns = 'http://www.w3.org/2000/svg';
  function svg(tag, attributes = {}) {
    const node = document.createElementNS(ns, tag);
    for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, value);
    return node;
  }

  const field = document.createElement('canvas');
  field.width = field.height = 128;
  const ink = field.getContext('2d');
  if (!ink) return { move() {} };
  const pixels = ink.createImageData(field.width, field.height);
  for (let y = 0; y < field.height; y++) {
    for (let x = 0; x < field.width; x++) {
      const dx = (2 * x + 1) / field.width - 1, dy = (2 * y + 1) / field.height - 1;
      const radius = Math.hypot(dx, dy);
      // The radial pull grows toward the shadow. Turn it toward the disk near
      // the rim so even a baseline passing through the center bends visibly.
      const falloff = Math.max(0, 1 - radius);
      const strength = falloff * falloff / Math.max(radius, 0.10);
      const angle = 0.96 * falloff, cosine = Math.cos(angle), sine = Math.sin(angle);
      const i = (y * field.width + x) * 4;
      pixels.data[i] = 128 - 127 * (dx * cosine - dy * sine) * strength;
      pixels.data[i + 1] = 128 - 127 * (dx * sine + dy * cosine) * strength;
      pixels.data[i + 2] = 255 * Math.min(1, falloff / 0.12);
      pixels.data[i + 3] = 255;
    }
  }
  ink.putImageData(pixels, 0, 0);
  const mapURL = field.toDataURL();
  const sheet = svg('svg', { class: 'gargantua-type-field', width: 0, height: 0, 'aria-hidden': 'true' });
  const defs = svg('defs');
  sheet.append(defs);
  document.body.append(sheet);

  const selector = [
    'h1,h2,h3,h4,h5,h6,p,li,dt,dd,td,th,pre,summary,figcaption',
    '.post-meta-item,.post-button a,.home-guide-links a,.home-guide-heading > a',
    '.footer-inner > div,.pagination > *, .tag-cloud-tags > a,.kb-tools,.code-tools'
  ].join(',');
  const visible = new Set();
  const active = new Map();
  let serial = 0, frame = 0;
  function schedule() {
    if (!frame) frame = requestAnimationFrame(update);
  }
  const observer = typeof IntersectionObserver === 'function' ? new IntersectionObserver(entries => {
    for (const entry of entries) {
      if (entry.isIntersecting) visible.add(entry.target);
      else visible.delete(entry.target);
    }
    schedule();
  }) : null;
  function discover() {
    for (const node of document.querySelectorAll(selector)) {
      if (observer) observer.observe(node);
      else visible.add(node);
    }
  }

  function attach(node) {
    const id = 'gargantua-glyph-' + (++serial);
    const filter = svg('filter', {
      id, filterUnits: 'userSpaceOnUse', primitiveUnits: 'userSpaceOnUse',
      'color-interpolation-filters': 'sRGB'
    });
    const neutral = svg('feFlood', { 'flood-color': '#808080', result: 'neutral' });
    const image = svg('feImage', { href: mapURL, preserveAspectRatio: 'none', result: 'local' });
    const combine = svg('feComposite', { in: 'local', in2: 'neutral', operator: 'over', result: 'field' });
    const bend = svg('feDisplacementMap', {
      in: 'SourceGraphic', in2: 'field', xChannelSelector: 'R', yChannelSelector: 'G', result: 'bent'
    });
    // A neutral byte is 128/255, not exactly 0.5. Composite the original
    // glyphs outside the field to keep even the finest strokes pixel-exact.
    const mask = svg('feColorMatrix', {
      in: 'local', type: 'matrix', result: 'footprint',
      values: '0 0 0 0 0  0 0 0 0 0  0 0 0 0 0  0 0 1 0 0'
    });
    const inner = svg('feComposite', { in: 'bent', in2: 'footprint', operator: 'in', result: 'inner' });
    const outer = svg('feComposite', { in: 'SourceGraphic', in2: 'footprint', operator: 'out', result: 'outer' });
    const merge = svg('feComposite', { in: 'inner', in2: 'outer', operator: 'arithmetic', k2: 1, k3: 1 });
    filter.append(neutral, image, combine, bend, mask, inner, outer, merge);
    defs.append(filter);
    node.style.setProperty('--gargantua-type-lens', 'url("#' + id + '")');
    node.classList.add('gargantua-type-bent');
    const parts = { filter, image, bend };
    active.set(node, parts);
    return parts;
  }

  function detach(node, parts) {
    node.classList.remove('gargantua-type-bent');
    node.style.removeProperty('--gargantua-type-lens');
    parts.filter.remove();
    active.delete(node);
  }

  function update() {
    frame = 0;
    const box = scene.getBoundingClientRect();
    const cx = box.left + box.width / 2, cy = box.top + box.height / 2;
    const radius = box.height * 0.76;
    // SVG maps each channel to [-scale / 2, scale / 2] in CSS pixels.
    const scale = Math.min(48, Math.max(19, box.height * 0.225));
    const padding = Math.ceil(scale / 2) + 2;
    const nearby = new Map();
    for (const node of visible) {
      const rect = node.getBoundingClientRect();
      if (!rect.height || !rect.width) continue;
      const dx = Math.max(rect.left - cx, cx - rect.right, 0);
      const dy = Math.max(rect.top - cy, cy - rect.bottom, 0);
      if (dx * dx + dy * dy > radius * radius) continue;
      // Large code listings can be much taller/wider than the GPU texture
      // limit. Target their visible line spans instead of filtering the table.
      if (rect.height > 2048 || rect.width > 4096) {
        if (node.tagName === 'PRE') {
          const top = Math.max(0, cy - radius, rect.top), bottom = Math.min(innerHeight, cy + radius, rect.bottom);
          const x = Math.min(innerWidth - 1, rect.right - 1, Math.max(1, rect.left + 1, cx));
          for (let y = top; y < bottom; y += 10) {
            const line = document.elementFromPoint(x, y)?.closest('pre .line');
            if (line && node.contains(line)) nearby.set(line, line.getBoundingClientRect());
          }
        }
        continue;
      }
      nearby.set(node, rect);
    }
    const keep = new Set();
    for (const [node, rect] of nearby) {
      let parent = node.parentElement;
      while (parent && !nearby.has(parent)) parent = parent.parentElement;
      if (parent) continue;
      keep.add(node);
      const { filter, image, bend } = active.get(node) || attach(node);
      filter.setAttribute('x', -padding);
      filter.setAttribute('y', -padding);
      filter.setAttribute('width', Math.ceil(rect.width) + 2 * padding);
      filter.setAttribute('height', Math.ceil(rect.height) + 2 * padding);
      image.setAttribute('x', cx - rect.left - radius);
      image.setAttribute('y', cy - rect.top - radius);
      image.setAttribute('width', 2 * radius);
      image.setAttribute('height', 2 * radius);
      bend.setAttribute('scale', scale);
    }
    for (const [node, parts] of active) if (!keep.has(node)) detach(node, parts);
  }

  window.addEventListener('scroll', schedule, { capture: true, passive: true });
  window.addEventListener('resize', schedule, { passive: true });
  document.addEventListener('pjax:success', discover);
  discover();
  schedule();
  return { move: schedule };
}
