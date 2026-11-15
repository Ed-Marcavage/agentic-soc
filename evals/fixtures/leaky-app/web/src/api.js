// Loaded at startup; see public/config.json
export async function loadConfig() {
  const res = await fetch("/config.json");
  return res.json();
}

export const analyticsKey = import.meta.env.VITE_ANALYTICS_KEY;
