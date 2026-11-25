#ifdef GL_FRAGMENT_PRECISION_HIGH
precision highp float;
#else
precision mediump float;
#endif

uniform vec2 uResolution;
uniform vec2 uLook;
uniform float uTime;

const float PI = 3.14159265;
// Distances are in Schwarzschild radii. The inner edge is near the ISCO.
const float INNER = 3.0;
const float OUTER = 8.4;

float hash(vec2 cell) {
  vec3 p = fract(cell.xyx * vec3(0.1031, 0.1030, 0.0973));
  p += dot(p, p.yzx + 33.33);
  return fract((p.x + p.y) * p.z);
}

float stars(vec3 direction) {
  vec2 sphere = vec2(atan(direction.z, direction.x), asin(clamp(direction.y, -1.0, 1.0)));
  vec2 grid = sphere * vec2(78.0, 84.0);
  vec2 cell = floor(grid);
  float seed = hash(cell);
  vec2 center = 0.2 + 0.6 * vec2(hash(cell + 7.3), hash(cell - 15.1));
  float size = mix(0.10, 0.23, seed);
  return step(0.89, seed) * (1.0 - smoothstep(0.0, size, length(fract(grid) - center)));
}

vec3 diskEmission(vec3 hit, vec3 toEye, float r) {
  vec3 tangent = vec3(-hit.z, 0.0, hit.x) / r;
  float beta = sqrt(0.5 / (r - 1.0));
  float doppler = sqrt(1.0 - beta * beta) / (1.0 - beta * dot(tangent, toEye));
  float shift = doppler * sqrt(1.0 - 1.0 / r);

  // Differential rotation lets neighboring filaments shear past each other.
  float phase = atan(hit.z, hit.x) - uTime * 1.9 / (r * sqrt(r));
  float wave = r * 8.7 + 2.4 * sin(phase * 2.0 + r * 0.78);
  float filaments = 0.76 + 0.17 * sin(wave) + 0.12 * sin(2.3 * wave - 3.0 * phase);
  float heat = exp(-0.23 * (r - INNER));
  float temperature = clamp((shift - 0.53) * 1.5 + 0.25 * heat, 0.0, 1.0);
  vec3 ember = vec3(0.98, 0.12, 0.085);
  vec3 ivory = vec3(1.0, 0.86, 0.62);
  vec3 color = mix(ember, ivory, temperature * temperature);
  return color * filaments * heat * (0.65 + 2.1 * shift * shift * shift);
}

// In the ray's orbital plane the Schwarzschild null orbit equation is
// u'' + u = 3u²/2. Its equivalent central acceleration conserves angular momentum.
vec3 acceleration(vec3 position, float invRadius, float angularMomentum2) {
  float inv2 = invRadius * invRadius;
  return -1.5 * angularMomentum2 * position * (inv2 * inv2 * invRadius);
}

void main() {
  vec2 screen = (2.0 * gl_FragCoord.xy - uResolution) / uResolution.y;
  float roll = 0.13 + 0.38 * uLook.x;
  vec2 film = mat2(cos(roll), -sin(roll), sin(roll), cos(roll)) * screen;
  float pitch = 0.16 + 0.14 * uLook.y;
  float yaw = 0.42 + 0.52 * uLook.x;
  vec3 outward = vec3(cos(pitch) * sin(yaw), sin(pitch), cos(pitch) * cos(yaw));
  vec3 right = vec3(cos(yaw), 0.0, -sin(yaw));
  vec3 up = cross(outward, right);
  vec3 position = 24.0 * outward;
  vec3 velocity = normalize(-outward + 0.227 * (film.x * right + film.y * up));
  vec3 momentum = cross(position, velocity);
  float angularMomentum2 = dot(momentum, momentum);

  vec3 light = vec3(0.0);
  float transmission = 1.0;
  float invRadius = 1.0 / 24.0;
  vec3 force = acceleration(position, invRadius, angularMomentum2);

  // Velocity Verlet integration. Each equatorial crossing is a possible disk
  // image, including the far side seen above and below the black hole.
  for (int step = 0; step < 104; step++) {
    float r = 1.0 / invRadius;
    float stride = clamp((r - 0.75) * 0.20, 0.065, 2.5);
    vec3 next = position + stride * (velocity + 0.5 * stride * force);
    float nextInv = inversesqrt(max(dot(next, next), 0.001));
    vec3 nextForce = acceleration(next, nextInv, angularMomentum2);
    vec3 nextVelocity = velocity + 0.5 * stride * (force + nextForce);

    if (position.y * next.y < 0.0) {
      float crossing = position.y / (position.y - next.y);
      vec3 hit = mix(position, next, crossing);
      float diskRadius = length(hit.xz);
      if (diskRadius > INNER && diskRadius < OUTER) {
        float opacity = smoothstep(INNER, INNER + 0.34, diskRadius)
                      * (1.0 - smoothstep(OUTER - 1.9, OUTER, diskRadius)) * 0.86;
        vec3 toEye = -normalize(mix(velocity, nextVelocity, crossing));
        light += transmission * opacity * diskEmission(hit, toEye, diskRadius);
        transmission *= 1.0 - opacity;
      }
    }

    // A thin emitting atmosphere softens the disk at grazing incidence.
    if (r > INNER && r < OUTER && abs(position.y) < 0.85) {
      float haze = exp(-7.5 * abs(position.y)) * (1.0 - smoothstep(INNER, OUTER, r));
      light += transmission * haze * stride * vec3(0.28, 0.049, 0.023);
    }
    position = next;
    velocity = nextVelocity;
    invRadius = nextInv;
    force = nextForce;

    if (invRadius > 0.985) {
      light += transmission * vec3(0.009, 0.004, 0.012);
      transmission = 0.0;
      break;
    }
    if (invRadius < 1.0 / 29.0 && dot(position, velocity) > 0.0) {
      float star = stars(normalize(velocity)) * 0.64;
      light += transmission * star * vec3(0.86, 0.68, 0.65);
      transmission *= 1.0 - star;
      break;
    }
  }

  float photonRing = exp(-24.0 * abs(sqrt(angularMomentum2) - 2.598));
  light += photonRing * vec3(0.32, 0.105, 0.053);
  light *= 0.98 + 0.035 * sin(uTime * 0.89);
  float alpha = max(1.0 - transmission, clamp(max(light.r, light.b), 0.0, 1.0));
  vec3 color = 1.0 - exp(-1.17 * light / max(alpha, 0.001));
  vec2 edge = abs(screen) / vec2(uResolution.x / uResolution.y, 1.0);
  float feather = 1.0 - smoothstep(0.78, 0.99, max(edge.x, edge.y));
  gl_FragColor = vec4(pow(color, vec3(0.86)), alpha * feather);
}
