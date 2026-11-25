#ifdef GL_FRAGMENT_PRECISION_HIGH
precision highp float;
#else
precision mediump float;
#endif

uniform vec2 uResolution;
uniform vec2 uLook;
uniform vec2 uVelocity;
uniform float uTime;
uniform sampler2D uCity;
// UV at the lens center and its full span in the CSS cover-sized city image.
uniform vec4 uCityUV;
uniform vec2 uPageY;

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
  vec2 center = 0.31 + 0.38 * vec2(hash(cell + 7.3), hash(cell - 15.1));
  float distance2 = dot(fract(grid) - center, fract(grid) - center);
  float core = exp(-distance2 / mix(0.005, 0.020, seed));
  float glow = exp(-30.0 * distance2) * (1.0 - smoothstep(0.05, 0.095, distance2));
  float pulse = 0.88 + 0.12 * sin(0.62 * uTime + 2.0 * PI * seed);
  return smoothstep(0.78, 0.99, seed) * pulse * (0.81 * core + 0.19 * glow);
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
  vec3 ember = vec3(0.91, 0.105, 0.13);
  vec3 ivory = vec3(1.0, 0.70, 0.53);
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
  float skyRadius = length(screen / vec2(uResolution.x / uResolution.y, 1.0));
  float envelope = 1.0 - smoothstep(0.50, 0.985, skyRadius);
  if (envelope <= 0.0) {
    gl_FragColor = vec4(0.0);
    return;
  }
  float roll = 0.13 + 0.38 * uLook.x + 0.19 * uVelocity.x;
  vec2 film = mat2(cos(roll), -sin(roll), sin(roll), cos(roll)) * screen;
  float pitch = clamp(0.16 + 0.14 * uLook.y + 0.08 * uVelocity.y, 0.025, 0.38);
  float yaw = 0.42 + 0.52 * uLook.x + 0.23 * uVelocity.x;
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
        float opacity = smoothstep(INNER, INNER + 0.55, diskRadius)
                      * (1.0 - smoothstep(4.3, OUTER, diskRadius)) * 0.83;
        vec3 toEye = -normalize(mix(velocity, nextVelocity, crossing));
        light += transmission * opacity * diskEmission(hit, toEye, diskRadius);
        transmission *= 1.0 - opacity;
      }
    }

    // Thin hot gas and a cooler, wider corona fade continuously past the visible disk.
    if (r > 2.4 && r < 11.5 && abs(position.y) < 3.6) {
      float density = smoothstep(2.4, 3.6, r) * (1.0 - smoothstep(4.0, 11.5, r));
      float altitude = abs(position.y) / (0.56 + 0.084 * r);
      float mist = exp(-1.36 * altitude * altitude) * (1.0 - smoothstep(2.0, 2.5, altitude));
      vec3 gas = exp(-5.5 * abs(position.y)) * vec3(0.23, 0.044, 0.032)
               + mist * vec3(0.066, 0.010, 0.017);
      light += transmission * density * stride * gas;
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
      float star = stars(normalize(velocity)) * (1.0 - smoothstep(0.43, 0.96, skyRadius));
      light += transmission * star * vec3(0.78, 0.58, 0.57);
      break;
    }
  }

  float ringDistance = abs(sqrt(angularMomentum2) - 2.598);
  float photonRing = exp(-24.0 * ringDistance);
  float aureole = exp(-3.4 * ringDistance);
  light += photonRing * vec3(0.25, 0.088, 0.054) + aureole * vec3(0.062, 0.012, 0.017);
  light *= 0.98 + 0.035 * sin(uTime * 0.89);

  // Tone-map emitted light before converting it to straight alpha. Low-density
  // stars and gas then blend with the actual sky without a dark fringe.
  vec3 emission = pow(1.0 - exp(-1.10 * light), vec3(0.94));
  float alpha = max(1.0 - transmission, max(emission.r, max(emission.g, emission.b)));
  if (uCityUV.z > 0.0 && transmission > 0.0) {
    // Map the extended background through a thin lens. Its deflection falls
    // with impact parameter; captured rays never sample the city.
    vec2 offset = (gl_FragCoord.xy / uResolution - 0.5) * vec2(1.0, -1.0);
    float deflection = min(1.55, 0.23 / max(dot(screen, screen), 0.10));
    vec2 sourceUV = uCityUV.xy + (1.0 - deflection) * offset * uCityUV.zw;
    vec3 city = texture2D(uCity, sourceUV).rgb;
    float y = uPageY.x + offset.y * uPageY.y;
    float shade = mix(0.21, 0.38, clamp((y - 0.12) / 0.40, 0.0, 1.0));
    shade = mix(shade, 0.90, clamp((y - 0.52) / 0.48, 0.0, 1.0));
    city = mix(city, vec3(0.047, 0.032, 0.044), shade);
    float bent = (1.0 - alpha) * (1.0 - smoothstep(0.40, 0.95, skyRadius)) * 0.85;
    emission += bent * city;
    alpha += bent;
  }
  gl_FragColor = vec4(emission / max(alpha, 0.0001), alpha * envelope);
}
