import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "BEHEMOTH",
  version: packageJson.version,
  copyright: `© ${currentYear}, BEHEMOTH.`,
  meta: {
    title: "BEHEMOTH — Autonomous Pentesting Console",
    description: "An LLM-powered autonomous penetration testing console",
  },
};
