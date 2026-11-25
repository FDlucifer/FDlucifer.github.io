(() => {
  'use strict';

  const root = document.documentElement;
  const animated = matchMedia('(any-hover: hover) and (any-pointer: fine) and (prefers-reduced-motion: no-preference)');
  const shaderURL = new URL('../shaders/gargantua.frag', document.currentScript.src);
  const sky = document.createElement('canvas');
  sky.className = 'gargantua-sky';
  sky.width = 320;
  sky.height = 180;
  sky.setAttribute('aria-hidden', 'true');
  const corona = document.createElement('span');
  corona.className = 'gargantua-corona';
  corona.setAttribute('aria-hidden', 'true');
  corona.hidden = true;
  document.body.append(sky, corona);

  let targetX = 0;
  let targetY = 0;
  let lookX = 0;
  let lookY = 0;
  let elapsed = 0;
  let lastPaint = null;
  let frame = 0;
  let onPage = true;
  let started = false;
  let sizeChanged = true;
  let gl;
  let uniforms;
  let fragmentSource;

  function updateFallback() {
    // These are actual ray-traced views. The center tile also works without JS.
    const column = Math.round((targetX + 1) * 2);
    const row = Math.round(1 - targetY);
    sky.parentElement.style.setProperty('--lens-column', column * 25 + '%');
    sky.parentElement.style.setProperty('--lens-row', row * 50 + '%');
  }

  function point(event) {
    if (event.pointerType !== 'mouse' || !animated.matches) {
      corona.hidden = true;
      return;
    }
    targetX = Math.max(-1, Math.min(1, 2 * event.clientX / innerWidth - 1));
    targetY = Math.max(-1, Math.min(1, 1 - 2 * event.clientY / innerHeight));
    if (!uniforms) updateFallback();

    // The OS paints the black hole at its native hotspot. Only its light is DOM-based.
    corona.style.transform = `translate3d(${event.clientX}px, ${event.clientY}px, 0)`;
    corona.hidden = false;
  }

  function leave() {
    corona.hidden = true;
    targetX = targetY = 0;
    if (!uniforms) updateFallback();
  }

  function compile(type, source) {
    const shader = gl.createShader(type);
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    if (gl.getShaderParameter(shader, gl.COMPILE_STATUS)) return shader;
    const reason = gl.getShaderInfoLog(shader);
    gl.deleteShader(shader);
    throw new Error(reason);
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
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      const reason = gl.getProgramInfoLog(program);
      gl.deleteProgram(program);
      throw new Error(reason);
    }
    gl.useProgram(program);
    gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    const corner = gl.getAttribLocation(program, 'corner');
    gl.enableVertexAttribArray(corner);
    gl.vertexAttribPointer(corner, 2, gl.FLOAT, false, 0, 0);
    uniforms = {
      resolution: gl.getUniformLocation(program, 'uResolution'),
      look: gl.getUniformLocation(program, 'uLook'),
      time: gl.getUniformLocation(program, 'uTime')
    };
    sizeChanged = true;
    sync();
  }

  function useFallback(error) {
    uniforms = null;
    root.classList.remove('gargantua-live');
    updateFallback();
    if (error) console.warn('Gargantua is using its pre-rendered views.', error);
  }

  async function initialize() {
    try {
      gl = sky.getContext('webgl', {
        alpha: true, antialias: false, depth: false, stencil: false,
        premultipliedAlpha: false, powerPreference: 'low-power'
      });
      if (!gl) return;
      const response = await fetch(shaderURL);
      if (!response.ok) throw new Error('Shader HTTP ' + response.status);
      fragmentSource = await response.text();
      prepare();
    } catch (error) {
      useFallback(error);
    }
  }

  function render(now) {
    frame = 0;
    if (!uniforms) return;
    if (!onPage || document.hidden || !animated.matches) {
      sync();
      return;
    }
    if (lastPaint === null || now - lastPaint >= 1000 / 24 - 0.5 || sizeChanged) {
      if (sizeChanged) {
        // Keep the pixel scale independent of DPR and bound the fragment workload.
        sky.width = Math.max(1, Math.min(384, Math.round(sky.clientWidth * 0.88)));
        sky.height = Math.max(1, Math.round(sky.width * 9 / 16));
        gl.viewport(0, 0, sky.width, sky.height);
        gl.uniform2f(uniforms.resolution, sky.width, sky.height);
        sizeChanged = false;
      }
      const dt = lastPaint === null ? 0 : Math.min((now - lastPaint) / 1000, 0.15);
      lastPaint = now;
      elapsed += dt;
      const easing = 1 - Math.exp(-9 * dt);
      lookX += (targetX - lookX) * easing;
      lookY += (targetY - lookY) * easing;
      gl.uniform2f(uniforms.look, lookX, lookY);
      gl.uniform1f(uniforms.time, elapsed);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
      root.classList.add('gargantua-live');
    }
    frame = requestAnimationFrame(render);
  }

  function sync() {
    if (!animated.matches || document.hidden || !onPage) {
      cancelAnimationFrame(frame);
      frame = 0;
      lastPaint = null;
      lookX = lookY = targetX = targetY = 0;
      corona.hidden = true;
      root.classList.remove('gargantua-live');
      updateFallback();
    } else if (!started) {
      started = true;
      initialize();
    } else if (uniforms && !frame) {
      frame = requestAnimationFrame(render);
    }
  }

  sky.addEventListener('webglcontextlost', event => {
    event.preventDefault();
    cancelAnimationFrame(frame);
    frame = 0;
    lastPaint = null;
    useFallback();
  });
  sky.addEventListener('webglcontextrestored', () => {
    try { prepare(); } catch (error) { useFallback(error); }
  });
  const markSizeChanged = () => { sizeChanged = true; };
  if (typeof ResizeObserver === 'function') {
    new ResizeObserver(markSizeChanged).observe(sky);
  } else {
    window.addEventListener('resize', markSizeChanged);
  }
  window.addEventListener('pointermove', point, { passive: true });
  document.documentElement.addEventListener('pointerleave', leave);
  window.addEventListener('pointercancel', leave);
  window.addEventListener('blur', leave);
  window.addEventListener('pagehide', () => { onPage = false; sync(); });
  window.addEventListener('pageshow', () => { onPage = true; sync(); });
  document.addEventListener('visibilitychange', sync);
  animated.addEventListener('change', sync);
  sync();
})();
