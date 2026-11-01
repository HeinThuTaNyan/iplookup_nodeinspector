if (
  window.location.hostname !== "127.0.0.1" &&
  window.location.hostname !== "localhost"
) {
  window.va = window.va || function () { (window.vaq = window.vaq || []).push(arguments); };
  const vaScript = document.createElement("script");
  vaScript.defer = true;
  vaScript.src = "/_vercel/insights/script.js";
  document.head.appendChild(vaScript);
}

const BACKEND_API_URL =
  window.location.hostname === "127.0.0.1" || window.location.hostname === "localhost"
    ? "http://127.0.0.1:5000/api/threat-intel"
    : "/api/threat-intel";

const COUNTRY_FALLBACKS = {
  MM: { name: "Myanmar", lat: 16.8409, lon: 96.1735, tz: "Asia/Yangon (UTC+06:30)" },
  US: { name: "United States", lat: 37.0902, lon: -95.7129, tz: "America/New_York" },
  SG: { name: "Singapore", lat: 1.3521, lon: 103.8198, tz: "Asia/Singapore" },
  TH: { name: "Thailand", lat: 13.7563, lon: 100.5018, tz: "Asia/Bangkok" },
  JP: { name: "Japan", lat: 35.6762, lon: 139.6503, tz: "Asia/Tokyo" },
  GB: { name: "United Kingdom", lat: 51.5074, lon: -0.1278, tz: "Europe/London" },
  DE: { name: "Germany", lat: 51.1657, lon: 10.4515, tz: "Europe/Berlin" },
  AU: { name: "Australia", lat: -33.8688, lon: 151.2093, tz: "Australia/Sydney" }
};

const HELP_TOPICS = ["ip", "vpn", "threat", "map"];

let loaderInterval = null;
let currentScanId = 0;
let activeHelpTopic = "ip";
let latestScanSummary = {
  ip: null, city: null, country: null, org: null, nodeRole: null, riskScore: null
};

function escapeHTML(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function sanitizeTargetInput(rawInput) {
  let cleaned = String(rawInput || "").trim();
  if (!cleaned) return "";
  cleaned = cleaned.replace(/^[a-zA-Z]+:\/\//, "");
  cleaned = cleaned.split("/")[0].split("?")[0].split("#")[0];
  if (cleaned.split(":").length === 2 && !cleaned.includes("::")) {
    cleaned = cleaned.split(":")[0];
  }
  return cleaned.trim();
}

function isValidIPv6Syntax(str) {
  if (!str || !str.includes(":")) return false;
  return /^[0-9a-fA-F:.]+$/.test(str) && str.length <= 45;
}

window.addEventListener("DOMContentLoaded", () => {
  setupEventListeners();
  lookupMyIP();
});

function setupEventListeners() {
  document.getElementById("ip-input").addEventListener("keypress", (e) => {
    if (e.key === "Enter") lookupIP();
  });

  document.getElementById("btn-scan").addEventListener("click", () => lookupIP());
  document.getElementById("btn-my-ip").addEventListener("click", lookupMyIP);

  document.querySelectorAll(".quick-chip").forEach((chip) => {
    chip.addEventListener("click", () => quickScan(chip.dataset.target));
  });

  document.getElementById("help-fab").addEventListener("click", () => toggleHelpPopover());

  document.querySelectorAll(".help-close-trigger").forEach((btn) => {
    btn.addEventListener("click", () => toggleHelpPopover(false));
  });

  document.querySelectorAll(".help-rescan-trigger").forEach((btn) => {
    btn.addEventListener("click", testMyVpnFromHelp);
  });

  document.querySelectorAll(".help-step-card").forEach((card) => {
    card.addEventListener("click", () => focusHelpTopic(card.dataset.topic, false));
    card.addEventListener("mouseenter", () => focusHelpTopic(card.dataset.topic, true));
    card.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        focusHelpTopic(card.dataset.topic, false);
      }
    });
  });

  document.getElementById("btn-prev-guide").addEventListener("click", () => stepHelpTopic(-1));
  document.getElementById("btn-next-guide").addEventListener("click", () => stepHelpTopic(1));

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") toggleHelpPopover(false);
  });

  document.addEventListener("click", (e) => {
    const popover = document.getElementById("help-popover");
    const widget = document.querySelector(".help-widget");
    if (popover && popover.classList.contains("open") && widget && !widget.contains(e.target)) {
      toggleHelpPopover(false);
    }
  });
}

function lookupMyIP() {
  document.getElementById("ip-input").value = "";
  lookupIP("");
}

function quickScan(target) {
  document.getElementById("ip-input").value = target;
  lookupIP(target);
}

function classifyReservedIP(rawInput) {
  if (!rawInput) return null;
  let input = rawInput.trim().toLowerCase();

  if (input === "localhost" || input === "localhost.localdomain") {
    return {
      ip: "127.0.0.1", version: "IPv4", isReserved: true,
      category: "LOOPBACK INTERFACE", rfc: "RFC 1122 (Section 3.2.1.3)",
      cidr: "127.0.0.0/8", badgeText: "NODE: LOOPBACK [LOCAL]",
      scope: "Host-Local Loopback",
      explanation: "Loopback traffic stays strictly inside your own device and never reaches the public internet."
    };
  }

  if (input.startsWith("::ffff:") && /^::ffff:(\d{1,3}\.){3}\d{1,3}$/.test(input)) {
    input = input.replace("::ffff:", "");
  }

  const ipv4Match = input.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const octets = ipv4Match.slice(1, 5).map(Number);
    if (octets.some((o) => o < 0 || o > 255)) {
      return { isInvalid: true, error: `Invalid IPv4 octet in '${rawInput}' (each octet must be 0–255).` };
    }
    const [a, b, c, d] = octets;

    if (a === 10) {
      return {
        ip: input, version: "IPv4", isReserved: true,
        category: "PRIVATE LAN NETWORK (CLASS A)", rfc: "RFC 1918",
        cidr: "10.0.0.0/8", badgeText: "NODE: PRIVATE LAN [RFC1918]",
        scope: "Internal Local Network",
        explanation: "Reserved for private enterprise and home local area networks (LANs) behind a NAT router. Not routable on the public internet."
      };
    }
    if (a === 172 && b >= 16 && b <= 31) {
      return {
        ip: input, version: "IPv4", isReserved: true,
        category: "PRIVATE LAN NETWORK (CLASS B)", rfc: "RFC 1918",
        cidr: "172.16.0.0/12", badgeText: "NODE: PRIVATE LAN [RFC1918]",
        scope: "Internal Local Network / Docker Bridge",
        explanation: "Reserved for private local networks, VPN tunnels, and container bridges. Not routable on the public internet."
      };
    }
    if (a === 192 && b === 168) {
      return {
        ip: input, version: "IPv4", isReserved: true,
        category: "PRIVATE HOME / OFFICE LAN", rfc: "RFC 1918",
        cidr: "192.168.0.0/16", badgeText: "NODE: PRIVATE LAN [RFC1918]",
        scope: "Local Wi-Fi / Router Subnet",
        explanation: "Assigned to devices or routers on a local home/office Wi-Fi network. Public websites only see your ISP's public router IP, never this local address."
      };
    }
    if (a === 127) {
      return {
        ip: input, version: "IPv4", isReserved: true,
        category: "LOCALHOST LOOPBACK", rfc: "RFC 1122",
        cidr: "127.0.0.0/8", badgeText: "NODE: LOOPBACK [LOCAL]",
        scope: "Host-Local Loopback",
        explanation: "Used by your computer to communicate with local servers running on the same machine."
      };
    }
    if (a === 100 && b >= 64 && b <= 127) {
      return {
        ip: input, version: "IPv4", isReserved: true,
        category: "CARRIER-GRADE NAT (CGNAT)", rfc: "RFC 6598",
        cidr: "100.64.0.0/10", badgeText: "NODE: ISP CGNAT [RFC6598]",
        scope: "ISP Shared Address Space",
        explanation: "Used by Fiber and Mobile ISPs (and Mesh VPNs like Tailscale) to share a single public IPv4 address across multiple customers."
      };
    }
    if (a === 169 && b === 254) {
      return {
        ip: input, version: "IPv4", isReserved: true,
        category: "LINK-LOCAL (APIPA)", rfc: "RFC 3927",
        cidr: "169.254.0.0/16", badgeText: "NODE: LINK-LOCAL [APIPA]",
        scope: "Physical Link Segment",
        explanation: "Automatically self-assigned when a device cannot reach a DHCP server (or used by cloud metadata services at 169.254.169.254)."
      };
    }
    if (a === 0) {
      return {
        ip: input, version: "IPv4", isReserved: true,
        category: "UNSPECIFIED / THIS NETWORK", rfc: "RFC 1122",
        cidr: "0.0.0.0/8", badgeText: "NODE: UNSPECIFIED [LOCAL]",
        scope: "Software Binding Meta-Address",
        explanation: "Represents 'all local IPv4 interfaces' when binding a server port or an uninitialized network address."
      };
    }
    if (
      (a === 192 && b === 0 && (c === 0 || c === 2)) ||
      (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113) ||
      (a === 198 && (b === 18 || b === 19))
    ) {
      return {
        ip: input, version: "IPv4", isReserved: true,
        category: "DOCUMENTATION / BENCHMARK TEST-NET", rfc: "RFC 5737 / RFC 2544",
        cidr: `${a}.${b}.${c}.0/24`, badgeText: "NODE: TEST-NET [RESERVED]",
        scope: "Documentation & Lab Testing",
        explanation: "Reserved by IANA for technical documentation, examples, and network benchmarking. Never assigned on the public internet."
      };
    }
    if (a >= 224 && a <= 239) {
      return {
        ip: input, version: "IPv4", isReserved: true,
        category: "MULTICAST GROUP ADDRESS", rfc: "RFC 5771",
        cidr: "224.0.0.0/4", badgeText: "NODE: MULTICAST [RESERVED]",
        scope: "One-to-Many Multicast Routing",
        explanation: "Reserved for IP multicast packet delivery (such as mDNS at 224.0.0.251 or SSDP)."
      };
    }
    if (a >= 240) {
      return {
        ip: input, version: "IPv4", isReserved: true,
        category: a === 255 && b === 255 && c === 255 && d === 255 ? "LIMITED BROADCAST" : "RESERVED CLASS E SPACE",
        rfc: "RFC 1112 / RFC 919", cidr: "240.0.0.0/4",
        badgeText: "NODE: RESERVED [IANA]", scope: "Reserved / Broadcast",
        explanation: "Reserved by IANA for future use or local subnet broadcast."
      };
    }
    return null;
  }

  if (input.includes(":")) {
    if (!isValidIPv6Syntax(input)) {
      return { isInvalid: true, error: `Invalid IPv6 address syntax in '${rawInput}'.` };
    }
    if (input === "::1" || input === "0:0:0:0:0:0:0:1") {
      return {
        ip: "::1", version: "IPv6", isReserved: true,
        category: "IPv6 LOOPBACK INTERFACE", rfc: "RFC 4291",
        cidr: "::1/128", badgeText: "NODE: LOOPBACK [IPv6]",
        scope: "Host-Local Loopback",
        explanation: "The IPv6 equivalent of 127.0.0.1. Traffic never leaves your local device."
      };
    }
    if (input === "::" || input === "0:0:0:0:0:0:0:0") {
      return {
        ip: "::", version: "IPv6", isReserved: true,
        category: "IPv6 UNSPECIFIED ADDRESS", rfc: "RFC 4291",
        cidr: "::/128", badgeText: "NODE: UNSPECIFIED [IPv6]",
        scope: "Software Binding Meta-Address",
        explanation: "Indicates the absence of an IPv6 address or binds a server to all local IPv6 interfaces."
      };
    }
    if (/^(fc|fd)[0-9a-f]{2}:/i.test(input)) {
      return {
        ip: input, version: "IPv6", isReserved: true,
        category: "UNIQUE LOCAL ADDRESS (ULA)", rfc: "RFC 4193",
        cidr: "fc00::/7", badgeText: "NODE: PRIVATE ULA [IPv6]",
        scope: "Internal Local IPv6 Subnet",
        explanation: "The IPv6 equivalent of RFC 1918 private LAN addresses. Routable only within private internal networks."
      };
    }
    if (/^fe[89ab][0-9a-f]:/i.test(input)) {
      return {
        ip: input, version: "IPv6", isReserved: true,
        category: "IPv6 LINK-LOCAL UNICAST", rfc: "RFC 4291",
        cidr: "fe80::/10", badgeText: "NODE: LINK-LOCAL [IPv6]",
        scope: "Physical Network Link",
        explanation: "Automatically configured on every IPv6 interface for local neighbor discovery and router advertisements."
      };
    }
    if (input.startsWith("2001:db8:") || input.startsWith("2001:0db8:")) {
      return {
        ip: input, version: "IPv6", isReserved: true,
        category: "IPv6 DOCUMENTATION PREFIX", rfc: "RFC 3849",
        cidr: "2001:db8::/32", badgeText: "NODE: DOCS PREFIX [IPv6]",
        scope: "Documentation & Examples",
        explanation: "Reserved exclusively for documentation, textbooks, and configuration examples."
      };
    }
    if (input.startsWith("ff")) {
      return {
        ip: input, version: "IPv6", isReserved: true,
        category: "IPv6 MULTICAST ADDRESS", rfc: "RFC 4291",
        cidr: "ff00::/8", badgeText: "NODE: MULTICAST [IPv6]",
        scope: "IPv6 Multicast Group",
        explanation: "Used for one-to-many IPv6 packet delivery across local or site links."
      };
    }
  }

  return null;
}

function bindCopyListeners() {
  document.querySelectorAll(".copyable-box").forEach((box) => {
    box.addEventListener("click", function () {
      copyToClipboard(this.dataset.copyVal, this);
    });
    box.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        copyToClipboard(this.dataset.copyVal, this);
      }
    });
  });
}

function renderReservedIPView(info) {
  stopTerminalLoader();
  const statusBadge = document.getElementById("status-indicator");
  const vpnBadge = document.getElementById("vpn-indicator");
  const backendBadge = document.getElementById("backend-indicator");
  const hostnameBadge = document.getElementById("hostname-badge");
  const intelContainer = document.getElementById("intel-container");
  const coordDisplay = document.getElementById("coord-display");

  statusBadge.textContent = `LOCAL // ${info.version}`;
  vpnBadge.className = "status-badge badge-clean";
  vpnBadge.textContent = info.badgeText;
  backendBadge.className = "status-badge badge-clean";
  backendBadge.textContent = "RFC CLASSIFIER: ACTIVE";
  hostnameBadge.textContent = `SCOPE: ${info.rfc}`;

  const displayV4 = info.version === "IPv4" ? info.ip : "N/A (IPv6 Range)";
  const displayV6 = info.version === "IPv6" ? info.ip : "N/A (IPv4 Range)";
  const canCopyV4 = info.version === "IPv4";
  const canCopyV6 = info.version === "IPv6";

  latestScanSummary = {
    ip: info.ip,
    city: "Local / Internal Network",
    country: info.rfc,
    org: info.category,
    nodeRole: info.category,
    riskScore: 0
  };
  updateHelpLiveSummary();

  intelContainer.innerHTML = `
    <div id="card-threat" class="intel-box threat-banner span-6 risk-reserved" data-guide="threat">
      <div class="threat-header-row">
        <div>
          <div class="intel-label">IANA Special-Purpose Registry // ${escapeHTML(info.rfc)}</div>
          <div class="threat-status-title">NON-ROUTABLE // ${escapeHTML(info.category)}</div>
        </div>
        <span class="threat-score-pill">${escapeHTML(info.cidr)}</span>
      </div>
      <div class="risk-meter-bg">
        <div class="risk-meter-fill" style="width: 100%; background: #00e5ff;"></div>
      </div>
      <div class="threat-flags-row">
        <span><strong>Routing Scope:</strong> ${escapeHTML(info.scope)} (Exempt from Public Threat Databases)</span>
        <span><strong>RFC Standard:</strong> ${escapeHTML(info.rfc)}</span>
      </div>
      <div class="intel-subtext" style="color: #cceeff; margin-top: 5px; white-space: normal; line-height: 1.35;">
        ${escapeHTML(info.explanation)}
      </div>
    </div>

    <div id="card-ipv4" class="intel-box span-3 ${canCopyV4 ? "copyable-box" : ""}" data-guide="ip" ${canCopyV4 ? `role="button" tabindex="0" data-copy-val="${escapeHTML(displayV4)}"` : ""}>
      <div class="intel-label-row"><div class="intel-label">IPv4 Address</div>${canCopyV4 ? '<span class="copy-hint">TAP TO COPY</span>' : ""}</div>
      <div class="intel-value" title="${escapeHTML(displayV4)}">${escapeHTML(displayV4)}</div>
      <div class="intel-subtext">Reserved Block: ${escapeHTML(info.cidr)}</div>
    </div>

    <div id="card-ipv6" class="intel-box span-3 ${canCopyV6 ? "copyable-box" : ""}" data-guide="ip" ${canCopyV6 ? `role="button" tabindex="0" data-copy-val="${escapeHTML(displayV6)}"` : ""}>
      <div class="intel-label-row"><div class="intel-label">IPv6 Address</div>${canCopyV6 ? '<span class="copy-hint">TAP TO COPY</span>' : ""}</div>
      <div class="intel-value" title="${escapeHTML(displayV6)}">${escapeHTML(displayV6)}</div>
      <div class="intel-subtext">${info.version === "IPv6" ? `Reserved Block: ${escapeHTML(info.cidr)}` : "Not Applicable"}</div>
    </div>

    <div id="card-isp" class="intel-box span-2" data-guide="ip">
      <div class="intel-label">ISP / Organization</div>
      <div class="intel-value">IANA Reserved Range</div>
      <div class="intel-subtext">${escapeHTML(info.rfc)}</div>
    </div>

    <div id="card-role" class="intel-box span-2" data-guide="vpn">
      <div class="intel-label">Fingerprinted Role</div>
      <div class="intel-value" title="${escapeHTML(info.category)}">${escapeHTML(info.category)}</div>
      <div class="intel-subtext">${escapeHTML(info.scope)}</div>
    </div>

    <div class="intel-box span-2 mobile-half">
      <div class="intel-label">ASN</div>
      <div class="intel-value">Non-Public ASN</div>
      <div class="intel-subtext">Internal Routing Only</div>
    </div>

    <div id="card-city" class="intel-box span-2 mobile-half" data-guide="ip">
      <div class="intel-label">City & Region</div>
      <div class="intel-value">Local Network</div>
      <div class="intel-subtext">No Public Geo Pin</div>
    </div>

    <div id="card-country" class="intel-box span-2 mobile-half" data-guide="ip">
      <div class="intel-label">Country & Postal</div>
      <div class="intel-value">Internal Subnet</div>
      <div class="intel-subtext">RFC Special Range</div>
    </div>

    <div class="intel-box span-2 mobile-half">
      <div class="intel-label">Timezone</div>
      <div class="intel-value">Device Local Time</div>
      <div class="intel-subtext">Internal Node</div>
    </div>
  `;

  bindCopyListeners();
  coordDisplay.textContent = `Coordinates: Non-routable address (${info.ip} is local/reserved per ${info.rfc}).`;

  const popover = document.getElementById("help-popover");
  if (popover && popover.classList.contains("open")) {
    focusHelpTopic(activeHelpTopic, true);
  }
}

function toggleHelpPopover(forceState) {
  const popover = document.getElementById("help-popover");
  const fab = document.getElementById("help-fab");
  if (!popover || !fab) return;

  const isOpen = forceState !== undefined ? forceState : !popover.classList.contains("open");

  if (isOpen) {
    popover.classList.add("open");
    popover.setAttribute("aria-hidden", "false");
    fab.setAttribute("aria-expanded", "true");
    updateHelpLiveSummary();
    focusHelpTopic(activeHelpTopic || "ip", false);
  } else {
    popover.classList.remove("open");
    popover.setAttribute("aria-hidden", "true");
    fab.setAttribute("aria-expanded", "false");
    clearGuideHighlights();
  }
}

function stepHelpTopic(direction) {
  const currentIndex = HELP_TOPICS.indexOf(activeHelpTopic);
  const nextIndex = (currentIndex + direction + HELP_TOPICS.length) % HELP_TOPICS.length;
  focusHelpTopic(HELP_TOPICS[nextIndex], false);
}

function clearGuideHighlights() {
  document.body.classList.remove("guide-mode-active");
  document.querySelectorAll(".guide-spotlight").forEach((el) => el.classList.remove("guide-spotlight"));
}

function scrollTargetIntoClearView(targetEl) {
  if (!targetEl) return;

  requestAnimationFrame(() => {
    const headerEl = document.querySelector("header");
    const popoverEl = document.getElementById("help-popover");
    const headerHeight = headerEl ? headerEl.getBoundingClientRect().height : 64;
    const rect = targetEl.getBoundingClientRect();

    let bottomObstruction = 24;
    if (popoverEl && popoverEl.classList.contains("open") && window.innerWidth <= 820) {
      bottomObstruction = popoverEl.getBoundingClientRect().height + 16;
    }

    const visibleTopBoundary = headerHeight + 10;
    const visibleBottomBoundary = window.innerHeight - bottomObstruction;
    const desiredScrollTop = Math.max(0, window.scrollY + rect.top - visibleTopBoundary);

    if (rect.top < visibleTopBoundary || rect.bottom > visibleBottomBoundary || window.innerWidth <= 820) {
      window.scrollTo({ top: desiredScrollTop, behavior: "smooth" });
    }
  });
}

function focusHelpTopic(topic, isHover = false) {
  if (isHover && (window.innerWidth <= 820 || "ontouchstart" in window)) return;

  activeHelpTopic = topic;
  const popover = document.getElementById("help-popover");
  if (!popover || !popover.classList.contains("open")) return;

  document.querySelectorAll(".help-step-card").forEach((card) => {
    const isMatch = card.dataset.topic === topic;
    card.classList.toggle("active", isMatch);
    const badge = card.querySelector(".step-badge");
    if (badge) badge.textContent = isMatch ? "HIGHLIGHTING" : "TAP TO VIEW";
  });

  const counterEl = document.getElementById("help-step-counter");
  if (counterEl) {
    const stepNum = HELP_TOPICS.indexOf(topic) + 1;
    counterEl.textContent = `${stepNum} / ${HELP_TOPICS.length}`;
  }

  clearGuideHighlights();
  document.body.classList.add("guide-mode-active");

  let targets = [];
  let scrollTarget = null;

  if (topic === "ip") {
    targets = [...document.querySelectorAll('[data-guide="ip"]')];
    scrollTarget = document.getElementById("card-ipv4") || targets[0];
  } else if (topic === "vpn") {
    const roleCard = document.getElementById("card-role");
    const headerBadge = document.getElementById("vpn-indicator");
    targets = [roleCard, headerBadge];
    scrollTarget = roleCard;
  } else if (topic === "threat") {
    const threatCard = document.getElementById("card-threat");
    targets = [threatCard];
    scrollTarget = threatCard;
  } else if (topic === "map") {
    const mapCard = document.getElementById("map-card");
    targets = [mapCard];
    scrollTarget = mapCard;
  }

  const validTargets = targets.filter(Boolean);
  validTargets.forEach((el) => el.classList.add("guide-spotlight"));

  if (!isHover && scrollTarget) scrollTargetIntoClearView(scrollTarget);
}

function updateHelpLiveSummary() {
  const summaryEl = document.getElementById("help-live-summary");
  if (!summaryEl) return;
  if (!latestScanSummary.ip) {
    summaryEl.textContent = "Scanning your connection telemetry...";
    return;
  }
  const loc = [latestScanSummary.city, latestScanSummary.country].filter(Boolean).join(", ") || "an unknown area";
  const isp = latestScanSummary.org || "an unlisted ISP";
  const role = latestScanSummary.nodeRole || "Standard Node";
  summaryEl.innerHTML = `Live Node: <strong>${escapeHTML(latestScanSummary.ip)}</strong> in <strong>${escapeHTML(loc)}</strong> via <strong>${escapeHTML(isp)}</strong> (Role: <strong>${escapeHTML(role)}</strong>).`;
}

function testMyVpnFromHelp() {
  toggleHelpPopover(false);
  lookupMyIP();
}

async function copyToClipboard(text, boxEl) {
  if (!text || text === "Unavailable" || text === "No IPv6 Detected") return;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const tempInput = document.createElement("textarea");
      tempInput.value = text;
      document.body.appendChild(tempInput);
      tempInput.select();
      document.execCommand("copy");
      document.body.removeChild(tempInput);
    }
    const hintEl = boxEl.querySelector(".copy-hint");
    if (hintEl) {
      const originalText = hintEl.dataset.defaultText || "TAP TO COPY";
      hintEl.dataset.defaultText = originalText;
      hintEl.textContent = "COPIED ✓";
      boxEl.classList.add("copied-flash");
      setTimeout(() => {
        hintEl.textContent = originalText;
        boxEl.classList.remove("copied-flash");
      }, 1400);
    }
  } catch (err) {}
}

function getAbuseRiskTheme(score, backendOnline = true, isWhitelisted = false) {
  if (!backendOnline || score === null || score === undefined || isNaN(Number(score))) {
    return {
      cssClass: "risk-neutral", barColor: "#666666",
      statusLabel: backendOnline ? "UNRATED // ABUSE SCORE UNAVAILABLE" : "OFFLINE // BACKEND TELEMETRY DISCONNECTED",
      pillLabel: backendOnline ? "Check AbuseIPDB ↗" : "OFFLINE"
    };
  }
  const numericScore = Math.max(0, Math.min(100, Number(score)));
  const wlSuffix = isWhitelisted ? " [WHITELISTED]" : "";

  if (numericScore <= 25) {
    return {
      cssClass: "risk-low", barColor: "#00ff66",
      statusLabel: `LOW RISK // CLEAN REPUTATION (${numericScore}%)${wlSuffix}`,
      pillLabel: `Abuse Score: ${numericScore}% ↗`
    };
  }
  if (numericScore <= 75) {
    return {
      cssClass: "risk-med", barColor: "#ffb700",
      statusLabel: `SUSPICIOUS // ELEVATED RISK (${numericScore}%)${wlSuffix}`,
      pillLabel: `Abuse Score: ${numericScore}% ↗`
    };
  }
  return {
    cssClass: "risk-high", barColor: "#ff3333",
    statusLabel: `HIGH RISK // MALICIOUS ACTIVITY (${numericScore}%)${wlSuffix}`,
    pillLabel: `Abuse Score: ${numericScore}% ↗`
  };
}

function startTerminalLoader(targetLabel) {
  const intelContainer = document.getElementById("intel-container");
  if (loaderInterval) clearInterval(loaderInterval);
  const safeTarget = escapeHTML(targetLabel || "CLIENT PUBLIC INTERFACE");
  const steps = [
    { pct: 18, bar: "[▓▓░░░░░░░░░░]", status: "STATUS: RESOLVING DUAL-STACK A/AAAA & PTR RECORDS..." },
    { pct: 42, bar: "[▓▓▓▓▓░░░░░░░]", status: "STATUS: QUERYING ABUSEIPDB V2 REPUTATION ENGINE..." },
    { pct: 68, bar: "[▓▓▓▓▓▓▓▓░░░░]", status: "STATUS: FINGERPRINTING SHODAN PORTS & VPN FEEDS..." },
    { pct: 89, bar: "[▓▓▓▓▓▓▓▓▓▓▓░]", status: "STATUS: AGGREGATING MULTI-GEO TELEMETRY NODES..." }
  ];
  let stepIdx = 0;
  const renderFrame = (step) => {
    intelContainer.innerHTML = `
      <div class="intel-box terminal-loader-box span-6">
        <div class="terminal-line">[SCANNING NODE: <strong>${safeTarget}</strong>] &gt; probing API...<span class="blinking-cursor">_</span></div>
        <div class="terminal-ascii-bar">${step.bar} ${step.pct}%</div>
        <div class="terminal-line muted">${step.status}</div>
      </div>
    `;
  };
  renderFrame(steps[0]);
  loaderInterval = setInterval(() => {
    stepIdx = (stepIdx + 1) % steps.length;
    renderFrame(steps[stepIdx]);
  }, 260);
}

function stopTerminalLoader() {
  if (loaderInterval) {
    clearInterval(loaderInterval);
    loaderInterval = null;
  }
}

async function fetchWithTimeout(url, timeoutMs = 2800, asText = false) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timer);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const parsed = asText ? await response.text() : await response.json();
    return Array.isArray(parsed) ? parsed[0] : parsed;
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

function pickFirst(...values) {
  for (const val of values) {
    if (val !== undefined && val !== null && val !== "" && val !== "N/A" && val !== "-") return val;
  }
  return null;
}

async function getOwnDualStackIPs() {
  const [v4Ipify, v6Ipify, v6Ident] = await Promise.allSettled([
    fetchWithTimeout("https://api.ipify.org?format=json", 2200),
    fetchWithTimeout("https://api64.ipify.org?format=json", 2200),
    fetchWithTimeout("https://v6.ident.me/", 2200, true)
  ]);
  let ipv4 = null;
  let ipv6 = null;
  if (v4Ipify.status === "fulfilled" && v4Ipify.value?.ip) {
    ipv4 = v4Ipify.value.ip.trim();
  }
  if (v6Ipify.status === "fulfilled" && v6Ipify.value?.ip) {
    const candidate = v6Ipify.value.ip.trim();
    if (candidate.includes(":")) ipv6 = candidate;
    else if (!ipv4) ipv4 = candidate;
  }
  if (!ipv6 && v6Ident.status === "fulfilled" && v6Ident.value) {
    const v6Candidate = v6Ident.value.trim();
    if (v6Candidate.includes(":")) ipv6 = v6Candidate;
  }
  return { ipv4, ipv6 };
}

async function resolveDNSFallback(target) {
  let ipv4 = null;
  let ipv6 = null;
  let hostname = null;
  if (!target) return { ipv4, ipv6, hostname };
  const isIPv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(target);
  const isIPv6 = isValidIPv6Syntax(target);

  try {
    if (isIPv4) {
      ipv4 = target;
      const reverseArpa = target.split(".").reverse().join(".") + ".in-addr.arpa";
      const ptrRes = await fetchWithTimeout(`https://dns.google/resolve?name=${reverseArpa}&type=PTR`, 2200);
      if (ptrRes?.Answer && ptrRes.Answer.length > 0) {
        hostname = ptrRes.Answer[0].data.replace(/\.$/, "");
        const aaaaRes = await fetchWithTimeout(`https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=AAAA`, 2000);
        const aaaaRecord = aaaaRes?.Answer?.find((rec) => rec.type === 28);
        if (aaaaRecord) ipv6 = aaaaRecord.data;
      }
    } else if (isIPv6) {
      ipv6 = target;
    } else {
      hostname = target;
      const [aRes, aaaaRes] = await Promise.allSettled([
        fetchWithTimeout(`https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=A`, 2200),
        fetchWithTimeout(`https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=AAAA`, 2200)
      ]);
      if (aRes.status === "fulfilled") {
        const aRecord = aRes.value?.Answer?.find((rec) => rec.type === 1);
        if (aRecord) ipv4 = aRecord.data;
      }
      if (aaaaRes.status === "fulfilled") {
        const aaaaRecord = aaaaRes.value?.Answer?.find((rec) => rec.type === 28);
        if (aaaaRecord) ipv6 = aaaaRecord.data;
      }
    }
  } catch (e) {}
  return { ipv4, ipv6, hostname };
}

async function fetchBackendThreatIntel(ip) {
  const backendBadge = document.getElementById("backend-indicator");
  const url = `${BACKEND_API_URL}?ip=${encodeURIComponent(ip || "")}`;
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const backendData = await fetchWithTimeout(url, 12000);
      if (backendData.abuseipdb_active) {
        backendBadge.className = "status-badge badge-clean";
        backendBadge.textContent = "API: ABUSEIPDB + SHODAN";
      } else {
        backendBadge.className = "status-badge badge-warn";
        backendBadge.textContent = "API: SHODAN ONLINE";
      }
      return backendData;
    } catch (err) {
      if (attempt === 1) {
        await new Promise((r) => setTimeout(r, 350));
        continue;
      }
      backendBadge.className = "status-badge badge-danger";
      backendBadge.textContent = err.message && err.message.includes("HTTP 429")
        ? "API: RATE LIMITED"
        : (err.message && err.message.includes("HTTP 500") ? "API: 500 ERROR" : "API: OFFLINE");
      return null;
    }
  }
}

function formatCompactRoleBadge(rawText) {
  if (!rawText) return "NODE: STANDARD";
  return rawText
    .replace("RESIDENTIAL ISP [CLEAN]", "RESIDENTIAL [CLEAN]")
    .replace("MOBILE CARRIER ISP [CLEAN]", "MOBILE ISP [CLEAN]")
    .replace("PUBLIC DNS / INFRASTRUCTURE", "PUBLIC DNS")
    .replace("CLOUD WEB / API SERVER", "CLOUD SERVER")
    .replace("DATACENTER / CLOUD HOST", "DATACENTER");
}

function mergeTelemetryData({ targetIP, ipv4Address, ipv6Address, backendIntel, geojs, freeip, ipwhois }) {
  const bGeo = backendIntel?.geo_fallback || {};
  const validWhois = ipwhois && ipwhois.success !== false ? ipwhois : {};
  const validFreeIp = freeip && freeip.ipAddress ? freeip : {};
  const validGeoJS = geojs && geojs.ip ? geojs : {};
  const resolvedIP = pickFirst(bGeo.ip, targetIP, ipv4Address, validGeoJS.ip, validFreeIp.ipAddress, validWhois.ip, ipv6Address);

  let rawASN = pickFirst(
    bGeo.asn,
    validWhois.connection?.asn ? `AS${validWhois.connection.asn}` : null,
    validGeoJS.asn ? `AS${validGeoJS.asn}` : null,
    validFreeIp.asn ? `AS${validFreeIp.asn}` : null
  );
  if (rawASN && !String(rawASN).toUpperCase().startsWith("AS")) rawASN = `AS${rawASN}`;

  let geoJsOrg = validGeoJS.organization_name || validGeoJS.organization || null;
  if (geoJsOrg && /^AS\d+\s+/i.test(geoJsOrg)) geoJsOrg = geoJsOrg.replace(/^AS\d+\s+/i, "").trim();

  const org = pickFirst(bGeo.org, validWhois.connection?.isp, validWhois.connection?.org, validFreeIp.asnOrganization, geoJsOrg);
  let defaultCidr = null;
  if (resolvedIP && /^(\d{1,3}\.){3}\d{1,3}$/.test(resolvedIP)) {
    const octets = resolvedIP.split(".");
    defaultCidr = `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
  }
  const network = pickFirst(bGeo.network, defaultCidr, bGeo.domain, validWhois.connection?.domain);
  const country_code = pickFirst(bGeo.country_code, validWhois.country_code, validFreeIp.countryCode, validGeoJS.country_code);
  const countryFallback = country_code ? COUNTRY_FALLBACKS[country_code.toUpperCase()] : null;
  const city = pickFirst(bGeo.city, validWhois.city, validFreeIp.cityName, validGeoJS.city);
  const region = pickFirst(bGeo.region, validWhois.region, validFreeIp.regionName, validGeoJS.region);
  const country_name = pickFirst(bGeo.country_name, validWhois.country, validFreeIp.countryName, validGeoJS.country, countryFallback?.name);
  const postal = pickFirst(bGeo.postal, validWhois.postal, validFreeIp.zipCode);
  const timezone = pickFirst(bGeo.timezone, validWhois.timezone?.id, validGeoJS.timezone, validFreeIp.timeZones?.[0], countryFallback?.tz);
  const utc_offset = pickFirst(bGeo.utc_offset, validWhois.timezone?.utc);
  const rawLat = pickFirst(bGeo.latitude, validWhois.latitude, validFreeIp.latitude, validGeoJS.latitude, countryFallback?.lat);
  const rawLon = pickFirst(bGeo.longitude, validWhois.longitude, validFreeIp.longitude, validGeoJS.longitude, countryFallback?.lon);
  const domain = pickFirst(bGeo.domain, validWhois.connection?.domain);
  const hostname = pickFirst(bGeo.hostname);

  const activeProviders = [];
  if (backendIntel?.active_backend_sources?.length) activeProviders.push(...backendIntel.active_backend_sources);
  if (validGeoJS.ip) activeProviders.push("GeoJS");
  if (validFreeIp.ipAddress) activeProviders.push("FreeIPAPI");
  if (validWhois.ip && !activeProviders.includes("ipwho.is")) activeProviders.push("ipwho.is");

  return {
    ip: resolvedIP,
    version: resolvedIP && resolvedIP.includes(":") ? "IPv6" : "IPv4",
    org, asn: rawASN, network, city, region, country_name, country_code, postal, timezone, utc_offset,
    latitude: !isNaN(parseFloat(rawLat)) ? parseFloat(rawLat) : null,
    longitude: !isNaN(parseFloat(rawLon)) ? parseFloat(rawLon) : null,
    domain, hostname, activeProviders
  };
}

function evaluateRealThreatIntel(backendIntel, targetIP) {
  const cleanIP = backendIntel?.ip || targetIP || "";
  const abuseReportURL = `https://www.abuseipdb.com/check/${encodeURIComponent(cleanIP)}`;
  if (!backendIntel) {
    return {
      backendOnline: false,
      theme: getAbuseRiskTheme(null, false, false),
      abuseReportURL,
      vpnBadgeText: "ROLE: OFFLINE",
      vpnBadgeClass: "badge-danger"
    };
  }
  const levelMap = { clean: "badge-clean", warn: "badge-warn", danger: "badge-danger" };
  const vpnBadgeClass = levelMap[backendIntel.role_badge_level] || "badge-clean";
  const vpnBadgeText = formatCompactRoleBadge(backendIntel.role_badge_text);
  const hasAbuseScore = backendIntel.abuse_score !== null && backendIntel.abuse_score !== undefined;
  const riskScore = hasAbuseScore ? Number(backendIntel.abuse_score) : null;
  const isWhitelisted = Boolean(backendIntel.is_whitelisted);
  const theme = getAbuseRiskTheme(riskScore, true, isWhitelisted);
  const scoreSourceLabel = hasAbuseScore ? "AbuseIPDB v2 Confidence Score" : "AbuseIPDB Key Not Configured (Neutral Mode)";

  const combinedFlags = [];
  if (backendIntel.anonymizer_flags?.length) combinedFlags.push(...backendIntel.anonymizer_flags);
  if (isWhitelisted) combinedFlags.push("Whitelisted Host");
  if (backendIntel.tags?.length) combinedFlags.push(...backendIntel.tags.map((t) => `Shodan:${t}`));

  const openPortsDisplay = backendIntel.detected_services?.length
    ? `${backendIntel.detected_services.join(", ")} (Total: ${backendIntel.open_ports.length})`
    : (backendIntel.open_ports?.length ? backendIntel.open_ports.join(", ") : "0 Open Ports (Filtered/NAT)");

  const totalReports = Number(backendIntel.total_reports) || 0;
  const distinctUsers = Number(backendIntel.distinct_users) || 0;
  const reportsHTML = hasAbuseScore
    ? `<a href="${escapeHTML(abuseReportURL)}" target="_blank" rel="noopener noreferrer" class="abuse-report-link">${totalReports} reports (${distinctUsers} sources) ↗</a>`
    : `<a href="${escapeHTML(abuseReportURL)}" target="_blank" rel="noopener noreferrer" class="abuse-report-link">View AbuseIPDB Page ↗</a>`;

  return {
    backendOnline: true,
    hasAbuseScore,
    riskScore: hasAbuseScore ? Math.max(0, Math.min(100, riskScore)) : 0,
    abuseReportURL,
    scoreSourceLabel,
    theme,
    vpnBadgeText,
    vpnBadgeClass,
    nodeRole: backendIntel.node_role,
    flagsText: combinedFlags.length > 0 ? combinedFlags.join(" • ") : "None (Standard Traffic)",
    openPorts: openPortsDisplay,
    vulns: backendIntel.vulns?.length ? backendIntel.vulns.slice(0, 4).join(", ") : "0 Known CVEs",
    reportsHTML
  };
}

async function lookupIP(customIP) {
  const scanId = ++currentScanId;
  const rawInput = customIP !== undefined ? customIP : document.getElementById("ip-input").value;
  const inputVal = sanitizeTargetInput(rawInput);

  const statusBadge = document.getElementById("status-indicator");
  const vpnBadge = document.getElementById("vpn-indicator");
  const hostnameBadge = document.getElementById("hostname-badge");
  const intelContainer = document.getElementById("intel-container");
  const coordDisplay = document.getElementById("coord-display");
  const mapFrame = document.getElementById("google-map");

  startTerminalLoader(inputVal || "LOCAL_INTERFACE");
  statusBadge.textContent = "PROBING...";
  vpnBadge.className = "status-badge";
  vpnBadge.textContent = "ROLE: SCANNING...";
  hostnameBadge.textContent = "HOST: RESOLVING...";

  try {
    if (inputVal) {
      const reservedDirect = classifyReservedIP(inputVal);
      if (reservedDirect) {
        if (reservedDirect.isInvalid) throw new Error(reservedDirect.error);
        renderReservedIPView(reservedDirect);
        return;
      }
    }

    let targetIP = inputVal;
    const isDomainInput = Boolean(inputVal && !/^(\d{1,3}\.){3}\d{1,3}$/.test(inputVal) && !inputVal.includes(":"));
    let preResolvedDNS = null;
    if (isDomainInput) {
      preResolvedDNS = await resolveDNSFallback(inputVal);
      if (scanId !== currentScanId) return;
      targetIP = preResolvedDNS.ipv4 || preResolvedDNS.ipv6 || "";
      if (!targetIP) {
        throw new Error(`Could not resolve DNS A/AAAA records for domain '${inputVal}'.`);
      }
      const reservedResolved = classifyReservedIP(targetIP);
      if (reservedResolved && reservedResolved.isReserved) {
        renderReservedIPView(reservedResolved);
        return;
      }
    }

    const geojsURL = targetIP
      ? `https://get.geojs.io/v1/ip/geo/${encodeURIComponent(targetIP)}.json`
      : "https://get.geojs.io/v1/ip/geo.json";
    const freeipURL = targetIP
      ? `https://freeipapi.com/api/json/${encodeURIComponent(targetIP)}`
      : "https://freeipapi.com/api/json/";
    const ipwhoisURL = targetIP
      ? `https://ipwho.is/${encodeURIComponent(targetIP)}`
      : "https://ipwho.is/";

    const [dualOrDnsSettled, backendSettled, geojsSettled, freeipSettled, ipwhoisSettled] = await Promise.allSettled([
      inputVal ? (preResolvedDNS ? Promise.resolve(preResolvedDNS) : resolveDNSFallback(targetIP)) : getOwnDualStackIPs(),
      fetchBackendThreatIntel(targetIP),
      fetchWithTimeout(geojsURL, 2600),
      fetchWithTimeout(freeipURL, 2600),
      fetchWithTimeout(ipwhoisURL, 2600)
    ]);

    if (scanId !== currentScanId) return;

    const dualOrDns = dualOrDnsSettled.status === "fulfilled" ? dualOrDnsSettled.value : {};
    const backendIntel = backendSettled.status === "fulfilled" ? backendSettled.value : null;
    const geojs = geojsSettled.status === "fulfilled" ? geojsSettled.value : null;
    const freeip = freeipSettled.status === "fulfilled" ? freeipSettled.value : null;
    const ipwhois = ipwhoisSettled.status === "fulfilled" ? ipwhoisSettled.value : null;

    if (ipwhois && ipwhois.success === false && /reserved|private|bogon/i.test(ipwhois.message || "")) {
      const fallbackReserved = classifyReservedIP(targetIP || ipwhois.ip);
      if (fallbackReserved && fallbackReserved.isReserved) {
        renderReservedIPView(fallbackReserved);
        return;
      }
    }

    const data = mergeTelemetryData({
      targetIP,
      ipv4Address: dualOrDns.ipv4 || null,
      ipv6Address: dualOrDns.ipv6 || null,
      backendIntel,
      geojs,
      freeip,
      ipwhois
    });

    if (!data.ip) throw new Error("Request failed to resolve node telemetries from any active provider.");
    const resolvedHostname = dualOrDns.hostname || data.hostname || null;

    stopTerminalLoader();

    const displayIPv4 = dualOrDns.ipv4 || (data.ip && !data.ip.includes(":") ? data.ip : "Unavailable");
    const displayIPv6 = dualOrDns.ipv6 || (data.ip && data.ip.includes(":") ? data.ip : "No IPv6 Detected");
    const canCopyV4 = displayIPv4 !== "Unavailable";
    const canCopyV6 = displayIPv6 !== "No IPv6 Detected";
    const threat = evaluateRealThreatIntel(backendIntel, data.ip);

    latestScanSummary = {
      ip: data.ip,
      city: data.city,
      country: data.country_name || data.country_code,
      org: data.org,
      nodeRole: threat.nodeRole || "Standard Node",
      riskScore: threat.riskScore
    };
    updateHelpLiveSummary();

    statusBadge.textContent = Boolean(dualOrDns.ipv4 && dualOrDns.ipv6) ? "DUAL-STACK" : (data.version || "IPv4");
    vpnBadge.className = `status-badge ${threat.vpnBadgeClass}`;
    vpnBadge.textContent = threat.vpnBadgeText;
    hostnameBadge.textContent = `HOST: ${resolvedHostname || data.domain || "No PTR Record"}`;

    const locationText = [data.city, data.region].filter(Boolean).join(", ") || "Unavailable";
    const countryText = data.country_name
      ? `${data.country_name}${data.country_code ? ` (${data.country_code})` : ""}${data.postal ? ` • ${data.postal}` : ""}`
      : (data.country_code || "Unavailable");
    const tzText = data.timezone ? `${data.timezone}${data.utc_offset ? ` (${data.utc_offset})` : ""}` : "Unavailable";
    const usageTypeText = backendIntel?.usage_type || "Port + VPN Analysis";

    intelContainer.innerHTML = `
      ${threat.backendOnline ? `
      <div id="card-threat" class="intel-box threat-banner span-6 ${escapeHTML(threat.theme.cssClass)}" data-guide="threat">
        <div class="threat-header-row">
          <div>
            <div class="intel-label">Threat Intelligence // Source: ${escapeHTML(threat.scoreSourceLabel)}</div>
            <div class="threat-status-title">${escapeHTML(threat.theme.statusLabel)}</div>
          </div>
          <a href="${escapeHTML(threat.abuseReportURL)}" target="_blank" rel="noopener noreferrer" class="threat-score-pill">${escapeHTML(threat.theme.pillLabel)}</a>
        </div>
        <div class="risk-meter-bg"><div class="risk-meter-fill" style="width: ${Number(threat.riskScore)}%; background: ${escapeHTML(threat.theme.barColor)};"></div></div>
        <div class="threat-flags-row">
          <span><strong>Anonymizer & Threat Flags:</strong> ${escapeHTML(threat.flagsText)}</span>
          <span><strong>AbuseIPDB Reports:</strong> ${threat.reportsHTML}</span>
        </div>
        <div class="threat-flags-row">
          <span><strong>Fingerprinted Services:</strong> ${escapeHTML(threat.openPorts)}</span>
          <span><strong>Shodan Known CVEs:</strong> ${escapeHTML(threat.vulns)}</span>
        </div>
      </div>` : `
      <div id="card-threat" class="intel-box threat-banner span-6 ${escapeHTML(threat.theme.cssClass)}" data-guide="threat">
        <div class="threat-header-row">
          <div>
            <div class="intel-label">Threat Intelligence // Neutral Fallback Mode</div>
            <div class="threat-status-title">${escapeHTML(threat.theme.statusLabel)}</div>
          </div>
          <span class="threat-score-pill">${escapeHTML(threat.theme.pillLabel)}</span>
        </div>
        <div class="intel-subtext" style="color: #aaa; margin-top: 6px; white-space: normal;">
          Backend server is offline or unreachable. Defaulting to neutral gray border with no false-positive alerts.
        </div>
      </div>`}

      <div id="card-ipv4" class="intel-box span-3 ${canCopyV4 ? "copyable-box" : ""}" data-guide="ip" ${canCopyV4 ? `role="button" tabindex="0" data-copy-val="${escapeHTML(displayIPv4)}"` : ""}>
        <div class="intel-label-row"><div class="intel-label">IPv4 Address</div>${canCopyV4 ? '<span class="copy-hint">TAP TO COPY</span>' : ""}</div>
        <div class="intel-value" title="${escapeHTML(displayIPv4)}">${escapeHTML(displayIPv4)}</div>
        <div class="intel-subtext">Prefix / Route: ${escapeHTML(data.network || "Standard IPv4")}</div>
      </div>

      <div id="card-ipv6" class="intel-box span-3 ${canCopyV6 ? "copyable-box" : ""}" data-guide="ip" ${canCopyV6 ? `role="button" tabindex="0" data-copy-val="${escapeHTML(displayIPv6)}"` : ""}>
        <div class="intel-label-row"><div class="intel-label">IPv6 Address</div>${canCopyV6 ? '<span class="copy-hint">TAP TO COPY</span>' : ""}</div>
        <div class="intel-value" title="${escapeHTML(displayIPv6)}">${escapeHTML(displayIPv6)}</div>
        <div class="intel-subtext">${dualOrDns.ipv6 ? (inputVal ? "Resolved via Reverse DNS" : "Direct ISP Dual-Stack") : "Not Available on Network"}</div>
      </div>

      <div id="card-isp" class="intel-box span-2" data-guide="ip">
        <div class="intel-label">ISP / Organization</div>
        <div class="intel-value" title="${escapeHTML(data.org || "Unavailable")}">${escapeHTML(data.org || "Unavailable")}</div>
        <div class="intel-subtext">${escapeHTML(data.domain ? `Domain: ${data.domain}` : "Active Provider")}</div>
      </div>

      <div id="card-role" class="intel-box span-2" data-guide="vpn">
        <div class="intel-label">Fingerprinted Role</div>
        <div class="intel-value" title="${escapeHTML(threat.nodeRole || "Backend Offline")}">${escapeHTML(threat.nodeRole || "Backend Offline")}</div>
        <div class="intel-subtext" title="${escapeHTML(usageTypeText)}">${escapeHTML(usageTypeText)}</div>
      </div>

      <div class="intel-box span-2 mobile-half">
        <div class="intel-label">ASN</div>
        <div class="intel-value">${escapeHTML(data.asn || "Unavailable")}</div>
        <div class="intel-subtext">Sources: ${Number(data.activeProviders.length || 1)} active</div>
      </div>

      <div id="card-city" class="intel-box span-2 mobile-half" data-guide="ip">
        <div class="intel-label">City & Region</div>
        <div class="intel-value" title="${escapeHTML(locationText)}">${escapeHTML(locationText)}</div>
        <div class="intel-subtext">Estimated Node Area</div>
      </div>

      <div id="card-country" class="intel-box span-2 mobile-half" data-guide="ip">
        <div class="intel-label">Country & Postal</div>
        <div class="intel-value" title="${escapeHTML(countryText)}">${escapeHTML(countryText)}</div>
        <div class="intel-subtext">Registry Jurisdiction</div>
      </div>

      <div class="intel-box span-2 mobile-half">
        <div class="intel-label">Timezone</div>
        <div class="intel-value" title="${escapeHTML(tzText)}">${escapeHTML(tzText)}</div>
        <div class="intel-subtext">Local Node Time</div>
      </div>
    `;

    bindCopyListeners();

    const popover = document.getElementById("help-popover");
    if (popover && popover.classList.contains("open")) focusHelpTopic(activeHelpTopic, true);

    if (data.latitude !== null && data.longitude !== null && !(data.latitude === 0 && data.longitude === 0)) {
      mapFrame.src = `https://www.google.com/maps?q=${encodeURIComponent(data.latitude)},${encodeURIComponent(data.longitude)}&z=12&output=embed`;
      coordDisplay.textContent = `Coordinates: ${data.latitude}, ${data.longitude} (Estimated ISP City Center • Sources: ${data.activeProviders.join(", ")})`;
    } else {
      coordDisplay.textContent = "Coordinates: Unavailable for this IP";
    }

  } catch (error) {
    if (scanId !== currentScanId) return;
    stopTerminalLoader();
    statusBadge.textContent = "ERROR";
    vpnBadge.className = "status-badge badge-danger";
    vpnBadge.textContent = "ROLE: ERROR";
    hostnameBadge.textContent = "HOST: ERROR";

    intelContainer.innerHTML = `
      <div class="intel-box terminal-error-box span-6">
        <div class="terminal-line" style="color: #ff3333; font-weight: bold;">[ERROR] &gt; Request failed to resolve node telemetries<span class="blinking-cursor" style="color: #ff3333;">_</span></div>
        <div class="terminal-line muted" style="color: #ffaaaa; margin-top: 4px;">DIAGNOSTIC: ${escapeHTML(error.message)}</div>
      </div>
    `;
  }
}