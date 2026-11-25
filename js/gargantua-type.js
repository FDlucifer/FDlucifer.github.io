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
      // Normalize the direction inside the opaque core. Everywhere visible,
      // displacement magnitude falls monotonically as (1 - radius) squared.
      const strength = Math.max(0, 1 - radius) ** 2 / Math.max(radius, 0.10);
      const i = (y * field.width + x) * 4;
      pixels.data[i] = 128 - 127 * dx * strength;
      pixels.data[i + 1] = 128 - 127 * dy * strength;
      pixels.data[i + 2] = 128;
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
      x: -4, y: -4, 'color-interpolation-filters': 'sRGB'
    });
    const neutral = svg('feFlood', { 'flood-color': '#808080', result: 'neutral' });
    const image = svg('feImage', { href: mapURL, preserveAspectRatio: 'none', result: 'local' });
    const combine = svg('feComposite', { in: 'local', in2: 'neutral', operator: 'over', result: 'field' });
    const bend = svg('feDisplacementMap', {
      in: 'SourceGraphic', in2: 'field', xChannelSelector: 'R', yChannelSelector: 'G'
    });
    filter.append(neutral, image, combine, bend);
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
    const radius = box.height * 0.69;
    // SVG maps each channel to [-scale / 2, scale / 2] in CSS pixels.
    const scale = Math.min(13.5, Math.max(7, box.height * 0.064));
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
      filter.setAttribute('width', Math.ceil(rect.width) + 8);
      filter.setAttribute('height', Math.ceil(rect.height) + 8);
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
