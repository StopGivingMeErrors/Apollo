import fs from "fs";
import { feature } from "topojson-client";

const topo = JSON.parse(fs.readFileSync("./src/assets/countries-110m.json", "utf8"));
const countries = feature(topo, topo.objects.countries);
const W = 1000;
const H = 500;

function proj(lon, lat) {
  return [((lon + 180) / 360) * W, ((90 - lat) / 180) * H];
}

/**
 * Rings that cross the 180th meridian arrive with longitudes that jump from
 * +179 to -179. Projected naively that draws a streak across the whole map.
 * Unwrapping keeps the ring continuous past ±180; callers then re-emit it
 * shifted by a full turn so the off-map half reappears on the other edge.
 */
function unwrap(ring) {
  let shift = 0;
  return ring.map((coord, i) => {
    if (i > 0) {
      const delta = coord[0] - ring[i - 1][0];
      if (delta > 180) shift -= 360;
      else if (delta < -180) shift += 360;
    }
    return [coord[0] + shift, coord[1]];
  });
}

function ringToPath(ring, lonOffset) {
  return (
    ring
      .map((c, i) => {
        const [x, y] = proj(c[0] + lonOffset, c[1]);
        return `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ") + "Z"
  );
}

function ringToPaths(rawRing) {
  const ring = unwrap(rawRing);
  const lons = ring.map((c) => c[0]);
  const offsets = [0];
  if (Math.max(...lons) > 180) offsets.push(-360);
  if (Math.min(...lons) < -180) offsets.push(360);
  return offsets.map((o) => ringToPath(ring, o)).join("");
}

function geomToPath(g) {
  if (!g) return "";
  if (g.type === "Polygon") return g.coordinates.map(ringToPaths).join("");
  if (g.type === "MultiPolygon") {
    return g.coordinates.map((p) => p.map(ringToPaths).join("")).join("");
  }
  return "";
}

const seen = new Set();
const paths = countries.features
  .map((f, i) => {
    let id = f.id == null ? `x${i}` : String(f.id);
    while (seen.has(id)) id = `${id}_${i}`;
    seen.add(id);
    return { id, d: geomToPath(f.geometry) };
  })
  .filter((p) => p.d);

const out = `export const WORLD_PATHS = ${JSON.stringify(paths)};
export const MAP_W = ${W};
export const MAP_H = ${H};
`;

fs.writeFileSync("./src/assets/worldPaths.js", out);
console.log("wrote", paths.length, "paths", out.length, "bytes");
