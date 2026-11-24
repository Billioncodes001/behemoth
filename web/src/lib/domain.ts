// Base-domain (eTLD+1) helpers shared by the findings website grouping and
// anywhere subdomains of the same registrable domain should cluster together.
// Multi-part public suffixes (e.g. .edu.ng, .co.uk) are handled with a small
// static list so "portal.uniosun.edu.ng" collapses to "uniosun.edu.ng", not
// "edu.ng".

const BASE_DOMAIN_SUFFIXES = new Set([
  "co.uk",
  "org.uk",
  "ac.uk",
  "gov.uk",
  "me.uk",
  "co.jp",
  "or.jp",
  "ne.jp",
  "ac.jp",
  "com.au",
  "net.au",
  "org.au",
  "edu.au",
  "gov.au",
  "co.nz",
  "net.nz",
  "org.nz",
  "com.br",
  "com.mx",
  "com.ar",
  "com.co",
  "com.pe",
  "com.uy",
  "com.eg",
  "com.ng",
  "edu.ng",
  "gov.ng",
  "org.ng",
  "net.ng",
  "sch.ng",
  "ac.ng",
  "co.ng",
  "com.gh",
  "com.ke",
  "co.ke",
  "co.tz",
  "co.za",
  "org.za",
  "com.zm",
  "co.in",
  "net.in",
  "org.in",
  "edu.in",
  "gov.in",
  "com.pk",
  "com.bd",
  "com.lk",
  "com.my",
  "com.sg",
  "co.id",
  "com.ph",
  "com.vn",
  "co.th",
  "com.hk",
  "com.tw",
  "com.cn",
  "gov.cn",
  "edu.cn",
  "org.cn",
  "net.cn",
  "com.tr",
  "com.sa",
  "com.ae",
  "com.qa",
  "com.kw",
  "com.bh",
  "com.om",
  "com.ua",
  "com.ru",
  "co.kr",
  "or.kr",
  "co.il",
  "com.es",
  "com.pt",
  "com.pl",
  "com.gr",
  "com.ro",
  "com.cz",
  "co.ca",
  "com.de",
  "com.fr",
  "com.it",
  "com.nl",
  "com.se",
  "com.no",
]);

const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

export function baseDomainOf(host: string): string {
  const h = (host || "").trim().toLowerCase().replace(/\.$/, "");
  if (!h || !h.includes(".")) return h;
  if (IPV4_RE.test(h) || h.includes(":")) return h;
  const parts = h.split(".");
  if (parts.length <= 2) return h;
  const last2 = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  if (BASE_DOMAIN_SUFFIXES.has(last2)) {
    return `${parts[parts.length - 3]}.${last2}`;
  }
  return `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
}
