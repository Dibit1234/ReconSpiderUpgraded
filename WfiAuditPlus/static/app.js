const els = {
  ssid: document.getElementById("ssid"),
  sensorSource: document.getElementById("sensor-source"),
  modePill: document.getElementById("mode-pill"),
  lastUpdated: document.getElementById("last-updated"),
  occupancy: document.getElementById("occupancy-score"),
  motion: document.getElementById("motion-score"),
  human: document.getElementById("human-score"),
  summary: document.getElementById("summary"),
  map: document.getElementById("map"),
  mapHover: document.getElementById("map-hover"),
  objects: document.getElementById("objects"),
  selectionEmpty: document.getElementById("selection-empty"),
  inspection: document.getElementById("inspection"),
  clearSelection: document.getElementById("clear-selection"),
  rescanButton: document.getElementById("rescan-button"),
  copyBssidButton: document.getElementById("copy-bssid-button"),
  exportButton: document.getElementById("export-button"),
  targetName: document.getElementById("target-name"),
  targetConfidence: document.getElementById("target-confidence"),
  targetPosition: document.getElementById("target-position"),
  targetVelocity: document.getElementById("target-velocity"),
  targetHeading: document.getElementById("target-heading"),
  targetTrail: document.getElementById("target-trail"),
  heatmap: document.getElementById("heatmap"),
  trendPath: document.getElementById("trend-path"),
  snapshotGrid: document.getElementById("snapshot-grid"),
  auditScore: document.getElementById("audit-score"),
  auditPosture: document.getElementById("audit-posture"),
  auditFindings: document.getElementById("audit-findings"),
  auditRecommendations: document.getElementById("audit-recommendations"),
};

const state = {
  lastData: null,
  selectedTargetId: null,
};

let requestInFlight = false;

function pct(value) {
  return `${Math.round(value * 100)}%`;
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(value, max));
}

function getSelectedTarget(data) {
  if (!state.selectedTargetId || !data.tracked_objects.length) {
    return null;
  }

  return data.tracked_objects.find((target) => target.id === state.selectedTargetId) || null;
}

function postureLabel(posture) {
  return (
    {
      good: "Good",
      review: "Review",
      "attention-needed": "Attention",
      unavailable: "Unavailable",
    }[posture] || "Review"
  );
}

function findingSeverityLabel(severity) {
  return severity ? severity.charAt(0).toUpperCase() + severity.slice(1) : "Info";
}

function showHover(target, event) {
  const tooltip = target.tooltip || {};
  els.mapHover.hidden = false;
  els.mapHover.innerHTML = `
    <div class="map-hover-title">${tooltip.ssid || target.label}</div>
    <div class="map-hover-row">Signal ${tooltip.signal_quality ?? "--"}%</div>
    <div class="map-hover-row">Channel ${tooltip.channel ?? "--"} • ${tooltip.radio_type || "Unknown"}</div>
    <div class="map-hover-row">${tooltip.authentication || "Unknown"} / ${tooltip.cipher || "Unknown"}</div>
  `;

  const mapRect = els.map.getBoundingClientRect();
  const x = clamp(event.clientX - mapRect.left + 14, 12, mapRect.width - 220);
  const y = clamp(event.clientY - mapRect.top - 10, 12, mapRect.height - 104);
  els.mapHover.style.left = `${x}px`;
  els.mapHover.style.top = `${y}px`;
}

function hideHover() {
  els.mapHover.hidden = true;
}

function renderRadar(data, selectedTarget) {
  els.map.innerHTML = "";
  hideHover();

  const radar = data.radar || {
    device: { x: 50, y: 50, label: "This device" },
    rings: [16, 28, 40],
    sectors: [],
  };

  radar.rings.forEach((ring) => {
    const node = document.createElement("div");
    node.className = "radar-ring";
    node.style.width = `${ring * 2}%`;
    node.style.height = `${ring * 2}%`;
    node.style.left = `${50 - ring}%`;
    node.style.top = `${50 - ring}%`;
    els.map.appendChild(node);
  });

  radar.sectors.forEach((sector) => {
    const node = document.createElement("div");
    node.className = "radar-sector-label";
    const midAngle = ((sector.start_angle + sector.end_angle) / 2) * (Math.PI / 180);
    const labelRadius = 44;
    node.style.left = `${50 + Math.cos(midAngle) * labelRadius}%`;
    node.style.top = `${50 + Math.sin(midAngle) * labelRadius}%`;
    node.textContent = `${sector.band} (${sector.count})`;
    els.map.appendChild(node);
  });

  const device = document.createElement("div");
  device.className = "device-node";
  device.style.left = `${radar.device?.x ?? 50}%`;
  device.style.top = `${radar.device?.y ?? 50}%`;
  device.innerHTML = `<span>${radar.device?.label || "This device"}</span>`;
  els.map.appendChild(device);

  data.tracked_objects.forEach((target) => {
    const node = document.createElement("button");
    node.type = "button";
    node.className = `target${selectedTarget && selectedTarget.id === target.id ? " target-selected" : ""}${target.connected_match ? " target-connected" : ""}`;
    node.style.left = `${clamp(target.x, 8, 92)}%`;
    node.style.top = `${clamp(target.y, 8, 92)}%`;
    node.title = `${target.label} ${target.signal_quality || 0}%`;
    node.setAttribute("aria-label", `Inspect ${target.label}`);
    node.addEventListener("mouseenter", (event) => showHover(target, event));
    node.addEventListener("mousemove", (event) => showHover(target, event));
    node.addEventListener("mouseleave", hideHover);
    node.addEventListener("click", () => {
      state.selectedTargetId = target.id;
      renderInspection(target);
      renderObjects(data, target);
      renderRadar(data, target);
    });
    els.map.appendChild(node);
  });
}

function renderObjects(data, selectedTarget) {
  els.objects.innerHTML = "";

  if (!data.tracked_objects.length) {
    els.objects.innerHTML = `
      <article class="object-card">
        <div class="object-title">No nearby scan data</div>
        <p>Windows may still need elevation or Location permission for full Wi-Fi scanning.</p>
      </article>
    `;
    return;
  }

  data.tracked_objects.forEach((target) => {
    const posture = target.inspection?.audit?.security_posture || "review";
    const card = document.createElement("article");
    card.className = `object-card${selectedTarget && selectedTarget.id === target.id ? " object-card-selected" : ""}`;
    card.innerHTML = `
      <div class="object-header">
        <div class="object-title">${target.label}</div>
        <span class="severity-pill severity-${posture}">${postureLabel(posture)}</span>
      </div>
      <p>BSSID: ${target.bssid || "Unavailable"}</p>
      <p>Signal: ${target.signal_quality ?? "--"}% (${target.rssi_dbm ?? "--"} dBm)</p>
      <p>Channel: ${target.channel ?? "--"} | ${target.band || "unknown"}</p>
      <p>Approximate relative position: ${target.relative?.distance_label || "unknown"}</p>
    `;
    card.addEventListener("click", () => {
      state.selectedTargetId = target.id;
      renderInspection(target);
      renderObjects(data, target);
      renderRadar(data, target);
    });
    els.objects.appendChild(card);
  });
}

function renderSnapshot(target) {
  const snapshot = target?.inspection?.snapshot || {};
  const entries = [
    ["Auth", snapshot.authentication || "Unknown"],
    ["Cipher", snapshot.cipher || "Unknown"],
    ["Radio", snapshot.radio_type || "Unknown"],
    ["Network type", snapshot.network_type || "Unknown"],
    ["OUI prefix", snapshot.oui_prefix || "Unavailable"],
    ["Basic rates", snapshot.basic_rates || "Unavailable"],
    ["Other rates", snapshot.other_rates || "Unavailable"],
    ["Same SSID", snapshot.same_ssid_count ?? "--"],
    ["Same channel", snapshot.same_channel_count ?? "--"],
    ["Proximity", snapshot.estimated_proximity || "unknown"],
  ];

  els.snapshotGrid.innerHTML = "";
  entries.forEach(([label, value]) => {
    const node = document.createElement("div");
    node.className = "snapshot-item";
    node.innerHTML = `<span>${label}</span><strong>${value}</strong>`;
    els.snapshotGrid.appendChild(node);
  });
}

function renderAudit(target) {
  const audit = target?.inspection?.audit;
  if (!audit) {
    els.auditScore.textContent = "--";
    els.auditPosture.textContent = "Unavailable";
    els.auditPosture.className = "pill";
    els.auditFindings.innerHTML = "";
    els.auditRecommendations.innerHTML = "";
    return;
  }

  els.auditScore.textContent = `${audit.overall_score}/100`;
  els.auditPosture.textContent = postureLabel(audit.security_posture);
  els.auditPosture.className = `pill severity-pill severity-${audit.security_posture}`;

  els.auditFindings.innerHTML = "";
  audit.findings.forEach((finding) => {
    const item = document.createElement("article");
    item.className = `finding finding-${finding.severity}`;
    item.innerHTML = `
      <div class="finding-head">
        <span class="severity-pill severity-${finding.severity}">${findingSeverityLabel(finding.severity)}</span>
        <strong>${finding.title}</strong>
      </div>
      <p>${finding.detail}</p>
    `;
    els.auditFindings.appendChild(item);
  });

  els.auditRecommendations.innerHTML = "";
  const recommendations = audit.recommendations?.length
    ? audit.recommendations
    : ["No extra remediation guidance is needed from the current passive snapshot."];
  recommendations.forEach((recommendation) => {
    const item = document.createElement("div");
    item.className = "recommendation-item";
    item.textContent = recommendation;
    els.auditRecommendations.appendChild(item);
  });
}

function renderInspection(target) {
  if (!target) {
    els.selectionEmpty.hidden = false;
    els.inspection.hidden = true;
    els.auditScore.textContent = "--";
    els.auditPosture.textContent = "Unavailable";
    els.snapshotGrid.innerHTML = "";
    return;
  }

  const history = target.inspection?.signal_history || [];
  const trend = target.inspection?.dominant_direction || "insufficient history";

  els.selectionEmpty.hidden = true;
  els.inspection.hidden = false;
  els.targetName.textContent = target.label;
  els.targetConfidence.textContent = `${target.signal_quality ?? 0}% quality`;
  els.targetPosition.textContent = target.bssid || "Unavailable";
  els.targetVelocity.textContent = `${target.signal_quality ?? "--"}% / ${target.rssi_dbm ?? "--"} dBm`;
  els.targetHeading.textContent = target.channel
    ? `Channel ${target.channel} | ${target.authentication || "Unknown"}`
    : "Channel unavailable";
  els.targetTrail.textContent = `${target.band || "unknown"} | ${history.length} samples | ${trend}`;

  renderHeatmap(target);
  renderTrendChart(history);
  renderSnapshot(target);
  renderAudit(target);
}

function renderHeatmap(target) {
  const matrix = target.inspection?.heatmap || [];
  if (!matrix.length) {
    els.heatmap.style.backgroundImage = "";
    return;
  }

  const cells = [];
  matrix.forEach((row, rowIndex) => {
    row.forEach((value, colIndex) => {
      const x = 8 + colIndex * 14;
      const y = 8 + rowIndex * 14;
      const alpha = 0.08 + value * 0.82;
      const radius = 11 + value * 12;
      cells.push(
        `radial-gradient(circle at ${x}% ${y}%, rgba(255, 193, 87, ${alpha}), rgba(255, 99, 71, ${value * 0.32}) ${radius * 0.55}%, transparent ${radius}%)`
      );
    });
  });

  els.heatmap.style.backgroundImage = cells.join(",");
}

function renderTrendChart(history) {
  if (!history.length) {
    els.trendPath.setAttribute("d", "M20 140 L220 140");
    return;
  }

  const maxPoints = Math.max(history.length - 1, 1);
  const points = history.map((value, index) => {
    const x = 20 + (index / maxPoints) * 200;
    const y = 140 - clamp(value, 0, 100) * 1.05;
    return `${Math.round(x)} ${Math.round(y)}`;
  });

  els.trendPath.setAttribute("d", `M${points.join(" L")}`);
}

async function refresh() {
  if (requestInFlight) {
    return;
  }

  requestInFlight = true;
  els.modePill.textContent = "Refreshing";

  try {
    const response = await fetch("/api/inference", { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`Request failed: ${response.status}`);
    }

    const data = await response.json();
    state.lastData = data;

    const selectedTarget = getSelectedTarget(data);
    const nearbyCount = data.telemetry?.nearby_network_count ?? 0;
    const modeText =
      data.telemetry?.status === "ok"
        ? "Audit live"
        : data.telemetry?.status === "limited"
          ? "Limited scan"
          : "Blocked";

    els.ssid.textContent = data.connected_network.ssid || "Unavailable";
    els.sensorSource.textContent = `Source: ${data.connected_network.source || "unavailable"}`;
    els.occupancy.textContent = pct(data.environment.occupancy_score);
    els.motion.textContent = pct(data.environment.motion_score);
    els.human.textContent = String(nearbyCount);
    els.summary.textContent = data.radar?.note || data.environment.summary;
    els.lastUpdated.textContent = `Last update: ${new Date(
      data.timestamp * 1000
    ).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}`;
    els.modePill.textContent = modeText;

    renderObjects(data, selectedTarget);
    renderInspection(selectedTarget);
    renderRadar(data, selectedTarget);
  } catch (error) {
    els.modePill.textContent = "Offline";
    els.lastUpdated.textContent = "Unable to refresh data right now.";
    els.summary.textContent =
      "The backend response is unavailable. Check the server connection and try again.";
    els.sensorSource.textContent = "Source: unavailable";
    els.ssid.textContent = "Unavailable";
    els.occupancy.textContent = "--";
    els.motion.textContent = "--";
    els.human.textContent = "--";
    els.objects.innerHTML = `
      <article class="object-card">
        <div class="object-title">No live Wi-Fi data</div>
        <p>The backend is offline or not responding.</p>
      </article>
    `;
    els.map.innerHTML = "";
    els.selectionEmpty.hidden = false;
    els.inspection.hidden = true;
    els.heatmap.style.backgroundImage = "";
    els.trendPath.setAttribute("d", "M20 140 L220 140");
    hideHover();
  } finally {
    requestInFlight = false;
  }
}

els.clearSelection.addEventListener("click", () => {
  state.selectedTargetId = null;
  if (state.lastData) {
    renderObjects(state.lastData, null);
    renderInspection(null);
    renderRadar(state.lastData, null);
  }
});

els.rescanButton.addEventListener("click", () => {
  refresh();
});

els.copyBssidButton.addEventListener("click", async () => {
  const target = state.lastData ? getSelectedTarget(state.lastData) : null;
  if (!target?.bssid || !navigator.clipboard) {
    return;
  }
  await navigator.clipboard.writeText(target.bssid);
  els.copyBssidButton.textContent = "Copied";
  setTimeout(() => {
    els.copyBssidButton.textContent = "Copy BSSID";
  }, 1200);
});

els.exportButton.addEventListener("click", () => {
  const target = state.lastData ? getSelectedTarget(state.lastData) : null;
  if (!target) {
    return;
  }
  const blob = new Blob([JSON.stringify(target, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `${(target.label || "ap").replace(/[^a-z0-9_-]+/gi, "_")}_${target.channel || "na"}.json`;
  link.click();
  URL.revokeObjectURL(url);
});

refresh();
setInterval(refresh, 2000);
