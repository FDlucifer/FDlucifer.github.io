(() => {
  'use strict';

  const root = document.documentElement;
  const motion = matchMedia('(prefers-reduced-motion: no-preference)');
  const fine = matchMedia('(any-hover: hover) and (any-pointer: fine)');
  const scriptURL = document.currentScript.src;
  const shaderURL = new URL('../shaders/gargantua.frag', scriptURL);
  const typeURL = new URL('./gargantua-type.js', scriptURL);
  const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

  function element(tag, className) {
    const node = document.createElement(tag);
    node.className = className;
    return node;
  }

  const layer = element('div', 'gargantua-layer');
  const scene = element('div', 'gargantua-scene');
  const sky = element('canvas', 'gargantua-sky');
  const poster = element('span', 'gargantua-poster');
  const handle = element('button', 'gargantua-handle');
  handle.type = 'button';
  handle.setAttribute('aria-label', '移动背景黑洞。方向键移动，回车复位');
  sky.setAttribute('aria-hidden', 'true');
  scene.append(poster, sky, handle);
  layer.append(scene);

  // Only the event horizon passes in front of the page. Copy its central pixels
  // from the same draw so the near-side disk crosses the shadow without a seam.
  const front = element('div', 'gargantua-front');
  const core = element('div', 'gargantua-core');
  const corePoster = element('span', 'gargantua-poster');
  const coreCanvas = element('canvas', 'gargantua-core-light');
  const coreInk = coreCanvas.getContext('2d');
  front.setAttribute('aria-hidden', 'true');
  core.append(corePoster, coreCanvas);
  front.append(core);
  const corona = element('span', 'gargantua-corona');
  corona.setAttribute('aria-hidden', 'true');
  corona.hidden = true;
  document.body.prepend(layer);
  document.body.append(front, corona);
  root.classList.add('gargantua-ready');

  const city = new Image();
  let gl, uniforms, cityTexture, fragmentSource;
  let cityReady = false;
  let started = false;
  let onPage = true;
  let projectionDirty = true;
  let frame = 0;
  let lastPaint = 0;
  let elapsed = 0;
  let targetX = 0, targetY = 0, lookX = 0, lookY = 0;
  let velocityX = 0, velocityY = 0;
  let placement = null;
  let grab = null;
  let draggedClick = false;
  let textLens, loadingTextLens;

  function prepareTextLens() {
    if (loadingTextLens) return;
    loadingTextLens = import(typeURL.href).then(module => {
      textLens = module.createTextLens(scene);
    }).catch(error => {
      loadingTextLens = null;
      console.warn('Gargantua text lens could not load.', error);
    });
  }

  function requestPaint() {
    if (!frame && onPage && !document.hidden) frame = requestAnimationFrame(render);
  }

  function place(x, y) {
    const width = layer.clientWidth, height = layer.clientHeight;
    if (!width || !height) return;
    const xFraction = clamp(x / width, 0, 1), yFraction = clamp(y / height, 0, 1);
    placement = { x: 2 * xFraction - 1, y: 1 - 2 * yFraction };
    for (const part of [scene, core]) {
      part.style.left = (100 * xFraction) + '%';
      part.style.top = (100 * yFraction) + '%';
    }
    targetX = placement.x;
    targetY = placement.y;
    projectionDirty = true;
    root.classList.add('gargantua-placed');
    textLens?.move();
    requestPaint();
  }

  function reset() {
    placement = null;
    root.classList.remove('gargantua-placed');
    for (const part of [scene, core]) {
      part.style.removeProperty('left');
      part.style.removeProperty('top');
    }
    targetX = targetY = velocityX = velocityY = 0;
    projectionDirty = true;
    textLens?.move();
    requestPaint();
  }

  // Listen on the document: an opaque hitbox above the page would steal its
  // links, inputs and scrolling. A grab can continue across any of those.
  const controls = 'button, input, textarea, select, label, summary, video, audio, iframe, [contenteditable]:not([contenteditable="false"]), [role="button"], [role="dialog"], .search-pop-overlay';
  function canGrab(target, x, y) {
    if (!(target instanceof Element) || (target !== handle && target.closest(controls))) return false;
    const box = scene.getBoundingClientRect();
    const dx = (x - box.left - box.width / 2) / (box.width * 0.425);
    const dy = (y - box.top - box.height / 2) / (box.height * 0.40);
    return dx * dx + dy * dy <= 1;
  }

  function begin(id, kind, x, y, target, time) {
    if (grab || !canGrab(target, x, y)) return false;
    const box = scene.getBoundingClientRect();
    grab = {
      id, kind, startX: x, startY: y, lastX: x, lastY: y, time, moving: false,
      offsetX: x - box.left - box.width / 2, offsetY: y - box.top - box.height / 2
    };
    prepareTextLens();
    return true;
  }

  function moveGrab(x, y, time) {
    if (!grab.moving) {
      if (Math.hypot(x - grab.startX, y - grab.startY) < (grab.kind === 'touch' ? 5 : 3)) return;
      grab.moving = true;
      root.classList.add('gargantua-dragging');
      if (grab.kind !== 'touch') {
        try { root.setPointerCapture(grab.id); } catch { /* Pointer already released. */ }
      }
      corona.hidden = true;
    }
    if (x === grab.lastX && y === grab.lastY) return;
    const dt = Math.max(8, time - grab.time);
    velocityX = clamp((x - grab.lastX) / dt, -1, 1);
    velocityY = clamp((grab.lastY - y) / dt, -1, 1);
    grab.lastX = x;
    grab.lastY = y;
    grab.time = time;
    place(x - grab.offsetX, y - grab.offsetY);
  }

  function endGrab(released = false) {
    if (!grab) return;
    const { id, kind } = grab;
    draggedClick = released && grab.moving;
    grab = null;
    root.classList.remove('gargantua-dragging', 'gargantua-can-grab');
    if (kind !== 'touch' && root.hasPointerCapture(id)) root.releasePointerCapture(id);
  }

  function point(event) {
    if (grab && grab.kind !== 'touch' && event.pointerId === grab.id) {
      if (!(event.buttons & 1)) endGrab();
      else moveGrab(event.clientX, event.clientY, event.timeStamp);
      return;
    }
    if (event.pointerType !== 'mouse' || grab) return;
    const { clientX: x, clientY: y } = event;
    const hover = canGrab(event.target, x, y);
    root.classList.toggle('gargantua-can-grab', hover);
    if (hover) prepareTextLens();
    corona.hidden = !motion.matches || hover;
    if (!corona.hidden) corona.style.transform = 'translate3d(' + x + 'px,' + y + 'px,0)';
    if (!motion.matches) return;
    const px = clamp(2 * x / layer.clientWidth - 1, -1, 1);
    const py = clamp(1 - 2 * y / layer.clientHeight, -1, 1);
    targetX = placement ? 0.82 * placement.x + 0.18 * px : px;
    targetY = placement ? 0.82 * placement.y + 0.18 * py : py;
    requestPaint();
  }

  function leave() {
    corona.hidden = true;
    root.classList.remove('gargantua-can-grab');
    if (!grab) {
      targetX = placement?.x || 0;
      targetY = placement?.y || 0;
      requestPaint();
    }
  }

  window.addEventListener('pointerdown', event => {
    draggedClick = false;
    if (event.pointerType === 'touch' || event.button !== 0 || !event.isPrimary ||
        event.ctrlKey || event.shiftKey || event.altKey || event.metaKey) return;
    begin(event.pointerId, event.pointerType, event.clientX, event.clientY, event.target, event.timeStamp);
  }, true);
  window.addEventListener('pointermove', point, { passive: true, capture: true });
  window.addEventListener('pointerup', event => {
    if (!grab || grab.kind === 'touch' || event.pointerId !== grab.id) return;
    if (grab.moving) moveGrab(event.clientX, event.clientY, event.timeStamp);
    endGrab(true);
  }, true);
  window.addEventListener('pointercancel', event => {
    if (grab && grab.kind !== 'touch' && event.pointerId === grab.id) endGrab();
  }, true);
  root.addEventListener('lostpointercapture', event => {
    if (event.target === root && grab?.kind !== 'touch' && grab?.id === event.pointerId) endGrab();
  });
  for (const type of ['selectstart', 'dragstart']) {
    document.addEventListener(type, event => { if (grab) event.preventDefault(); }, true);
  }
  window.addEventListener('click', event => {
    if (draggedClick && event.detail) {
      event.preventDefault();
      event.stopImmediatePropagation();
    }
    draggedClick = false;
  }, true);

  // Reserve a one-finger gesture only when it starts on the lens. Elsewhere
  // touch keeps its native scroll/zoom, including when it passes over the lens.
  window.addEventListener('touchstart', event => {
    draggedClick = false;
    if (event.touches.length !== 1) { endGrab(); return; }
    const t = event.changedTouches[0];
    begin(t.identifier, 'touch', t.clientX, t.clientY, event.target, event.timeStamp);
  }, { passive: true, capture: true });
  window.addEventListener('touchmove', event => {
    if (grab?.kind !== 'touch') return;
    const t = Array.from(event.changedTouches).find(touch => touch.identifier === grab.id);
    if (!t) return;
    if (event.cancelable) event.preventDefault();
    moveGrab(t.clientX, t.clientY, event.timeStamp);
  }, { passive: false, capture: true });
  for (const type of ['touchend', 'touchcancel']) {
    window.addEventListener(type, event => {
      if (grab?.kind !== 'touch') return;
      const t = Array.from(event.changedTouches).find(touch => touch.identifier === grab.id);
      if (!t) return;
      if (type === 'touchend' && grab.moving) moveGrab(t.clientX, t.clientY, event.timeStamp);
      endGrab(type === 'touchend');
    }, { passive: true, capture: true });
  }
  handle.addEventListener('keydown', event => {
    const delta = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] }[event.key];
    if (!delta && event.key !== 'Home') return;
    event.preventDefault();
    if (!delta) { reset(); return; }
    const box = scene.getBoundingClientRect();
    const step = event.shiftKey ? 64 : 16;
    velocityX = delta[0] * 0.55;
    velocityY = -delta[1] * 0.55;
    prepareTextLens();
    place(box.left + box.width / 2 + delta[0] * step, box.top + box.height / 2 + delta[1] * step);
  });
  handle.addEventListener('click', event => { if (event.detail === 0) reset(); });

  function updatePoster(x, y) {
    const column = Math.round((clamp(x, -1, 1) + 1) * 2);
    const row = Math.round(1 - clamp(y, -1, 1));
    const roll = 0.38 * (column / 2 - 1 - x);
    for (const tile of [poster, corePoster]) {
      tile.style.backgroundPosition = (column * 25) + '% ' + (row * 50) + '%';
      tile.style.transform = 'rotate(' + roll.toFixed(4) + 'rad)';
    }
  }

  function compile(type, source) {
    const shader = gl.createShader(type);
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    if (gl.getShaderParameter(shader, gl.COMPILE_STATUS)) return shader;
    const message = gl.getShaderInfoLog(shader);
    gl.deleteShader(shader);
    throw new Error(message);
  }

  function uploadCity() {
    if (!cityTexture || !city.naturalWidth || gl.isContextLost()) return;
    gl.bindTexture(gl.TEXTURE_2D, cityTexture);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, city);
    cityReady = true;
    projectionDirty = true;
    requestPaint();
  }

  function prepare() {
    if (!fragmentSource || gl.isContextLost()) return;
    const vertex = compile(gl.VERTEX_SHADER,
      'attribute vec2 corner; void main() { gl_Position = vec4(corner, 0.0, 1.0); }');
    const fragment = compile(gl.FRAGMENT_SHADER, fragmentSource);
    const program = gl.createProgram();
    gl.attachShader(program, vertex);
    gl.attachShader(program, fragment);
    gl.linkProgram(program);
    gl.deleteShader(vertex);
    gl.deleteShader(fragment);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(program));
    gl.useProgram(program);
    gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    const corner = gl.getAttribLocation(program, 'corner');
    gl.enableVertexAttribArray(corner);
    gl.vertexAttribPointer(corner, 2, gl.FLOAT, false, 0, 0);
    uniforms = {};
    for (const name of ['uResolution', 'uLook', 'uVelocity', 'uTime', 'uCityUV', 'uPageY']) {
      uniforms[name] = gl.getUniformLocation(program, name);
    }
    cityTexture = gl.createTexture();
    gl.bindTexture(gl.TEXTURE_2D, cityTexture);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, 1, 1, 0, gl.RGBA, gl.UNSIGNED_BYTE, new Uint8Array(4));
    gl.uniform1i(gl.getUniformLocation(program, 'uCity'), 0);
    uploadCity();
    projectionDirty = true;
    requestPaint();
  }

  function useFallback(error) {
    uniforms = cityTexture = null;
    cityReady = false;
    root.classList.remove('gargantua-live');
    updatePoster(lookX, lookY);
    if (error) console.warn('Gargantua is using its pre-rendered views.', error);
  }

  async function initialize() {
    try {
      gl = sky.getContext('webgl', {
        alpha: true, antialias: false, depth: false, stencil: false,
        premultipliedAlpha: false, powerPreference: 'low-power'
      });
      if (!gl) return;
      city.onload = uploadCity;
      city.src = new URL('../images/cyberpunk-pixel-city.webp', scriptURL).href;
      const response = await fetch(shaderURL);
      if (!response.ok) throw new Error('Shader HTTP ' + response.status);
      fragmentSource = await response.text();
      prepare();
    } catch (error) { useFallback(error); }
  }

  function updateProjection() {
    const box = scene.getBoundingClientRect();
    const width = clamp(Math.round(box.width * 0.88), 1, 384);
    const height = Math.max(1, Math.round(width * 9 / 16));
    if (sky.width !== width || sky.height !== height) {
      sky.width = width;
      sky.height = height;
      gl.viewport(0, 0, width, height);
    }
    gl.uniform2f(uniforms.uResolution, width, height);
    const vw = layer.clientWidth, vh = layer.clientHeight;
    const centerX = box.left + box.width / 2, centerY = box.top + box.height / 2;
    if (cityReady && vw && vh) {
      const scale = Math.max(vw / city.naturalWidth, vh / city.naturalHeight);
      const coverW = city.naturalWidth * scale, coverH = city.naturalHeight * scale;
      const css = getComputedStyle(layer);
      const left = (vw - coverW) * parseFloat(css.getPropertyValue('--city-x')) / 100;
      const top = (vh - coverH) * parseFloat(css.getPropertyValue('--city-y')) / 100;
      gl.uniform4f(uniforms.uCityUV, (centerX - left) / coverW, (centerY - top) / coverH,
        box.width / coverW, box.height / coverH);
      gl.uniform2f(uniforms.uPageY, centerY / vh, box.height / vh);
    }
    projectionDirty = false;
  }

  function paintCore() {
    if (!coreInk) return;
    const side = Math.max(1, Math.round(sky.height * 0.58));
    if (coreCanvas.width !== side || coreCanvas.height !== side) {
      coreCanvas.width = coreCanvas.height = side;
    }
    coreInk.clearRect(0, 0, side, side);
    coreInk.drawImage(sky, (sky.width - side) / 2, (sky.height - side) / 2, side, side, 0, 0, side, side);
  }

  function render(now) {
    frame = 0;
    if (!onPage || document.hidden) return;
    const realtime = uniforms && motion.matches;
    const interval = 1000 / (fine.matches ? 24 : 18);
    if (realtime && lastPaint && now - lastPaint < interval - 0.5) {
      requestPaint();
      return;
    }
    const dt = lastPaint ? Math.min((now - lastPaint) / 1000, 0.15) : 1 / 30;
    lastPaint = now;
    const easing = motion.matches ? 1 - Math.exp(-10 * dt) : 1;
    const decay = motion.matches ? Math.exp(-5.5 * dt) : 0;
    lookX += (targetX - lookX) * easing;
    lookY += (targetY - lookY) * easing;
    velocityX *= decay;
    velocityY *= decay;
    if (realtime) {
      if (projectionDirty) updateProjection();
      elapsed += dt * (1 + 0.55 * Math.hypot(velocityX, velocityY));
      gl.uniform2f(uniforms.uLook, lookX, lookY);
      gl.uniform2f(uniforms.uVelocity, velocityX, velocityY);
      gl.uniform1f(uniforms.uTime, elapsed);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
      paintCore();
      root.classList.add('gargantua-live');
    } else {
      updatePoster(lookX + velocityX * 0.5, lookY + velocityY * 0.5);
    }
    const settling = Math.abs(targetX - lookX) + Math.abs(targetY - lookY) +
      Math.abs(velocityX) + Math.abs(velocityY) > 0.005;
    if (realtime || settling) requestPaint();
    else lastPaint = 0;
  }

  function resize() {
    projectionDirty = true;
    textLens?.move();
    requestPaint();
  }

  function sync() {
    cancelAnimationFrame(frame);
    frame = lastPaint = 0;
    if (!onPage || document.hidden || !motion.matches) {
      endGrab();
      corona.hidden = true;
      root.classList.remove('gargantua-live');
      velocityX = velocityY = 0;
      updatePoster(targetX, targetY);
    }
    if (!onPage || document.hidden) return;
    if (motion.matches && !started) { started = true; initialize(); }
    requestPaint();
  }
  sky.addEventListener('webglcontextlost', event => { event.preventDefault(); useFallback(); requestPaint(); });
  sky.addEventListener('webglcontextrestored', () => {
    try { prepare(); } catch (error) { useFallback(error); }
  });
  if (typeof ResizeObserver === 'function') {
    const observer = new ResizeObserver(resize);
    observer.observe(layer);
    observer.observe(scene);
  }
  window.addEventListener('resize', resize);
  root.addEventListener('pointerleave', leave);
  window.addEventListener('blur', () => { endGrab(); leave(); });
  window.addEventListener('pagehide', () => { onPage = false; sync(); });
  window.addEventListener('pageshow', () => { onPage = true; sync(); });
  document.addEventListener('visibilitychange', sync);
  motion.addEventListener('change', sync);
  if ('requestIdleCallback' in window) window.requestIdleCallback(prepareTextLens, { timeout: 800 });
  else window.setTimeout(prepareTextLens, 100);
  sync();
})();
