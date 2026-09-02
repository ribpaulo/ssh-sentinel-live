const refreshIntervalMs = 4000;

const connectionStatus = document.querySelector("#connection-status");
const eventCount = document.querySelector("#event-count");
const activeAlertCount = document.querySelector("#active-alert-count");
const lastUpdated = document.querySelector("#last-updated");
const eventCountBadge = document.querySelector("#event-count-badge");
const alertCountBadge = document.querySelector("#alert-count-badge");
const eventsBody = document.querySelector("#events-body");
const alertsBody = document.querySelector("#alerts-body");
const alertDialog = document.querySelector("#alert-dialog");
const alertDialogTitle = document.querySelector("#alert-dialog-title");
const alertDescription = document.querySelector("#alert-description");
const alertMetadata = document.querySelector("#alert-metadata");
const alertEventsBody = document.querySelector("#alert-events-body");

let refreshTimer = null;
let refreshInProgress = false;

function displayValue(value) {
    return value === null || value === undefined || value === "" ? "—" : String(value);
}

function formatTimestamp(value) {
    if (!value) return "—";
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return String(value);
    return new Intl.DateTimeFormat("de-CH", {
        dateStyle: "short",
        timeStyle: "medium",
    }).format(parsed);
}

function appendCell(row, value, className = "") {
    const cell = document.createElement("td");
    cell.textContent = displayValue(value);
    if (className) cell.className = className;
    row.append(cell);
    return cell;
}

function badge(value, kind) {
    const element = document.createElement("span");
    const normalized = String(value).toLowerCase().replaceAll("_", "-");
    element.className = `data-badge ${kind}-${normalized}`;
    element.textContent = displayValue(value);
    return element;
}

function emptyRow(columnCount, message) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = columnCount;
    cell.className = "table-empty";
    cell.textContent = message;
    row.append(cell);
    return row;
}

function renderEvents(events) {
    const rows = events.map((event) => {
        const row = document.createElement("tr");
        appendCell(row, formatTimestamp(event.event_timestamp), "timestamp-cell");
        const typeCell = appendCell(row, "");
        typeCell.append(badge(event.event_type, "event"));
        appendCell(row, event.hostname);
        appendCell(row, event.ip_address, "mono-cell");
        appendCell(row, event.username);
        appendCell(row, event.auth_method);
        appendCell(row, event.source, "source-cell");
        return row;
    });
    eventsBody.replaceChildren(...(rows.length ? rows : [emptyRow(7, "Noch keine SSH-Events gespeichert.")]));
    eventCount.textContent = String(events.length);
    eventCountBadge.textContent = `${events.length} geladen`;
}

function renderAlerts(alerts) {
    const rows = alerts.map((alert) => {
        const row = document.createElement("tr");
        appendCell(row, alert.id, "mono-cell");
        appendCell(row, formatTimestamp(alert.created_at), "timestamp-cell");
        const severityCell = appendCell(row, "");
        severityCell.append(badge(alert.severity, "severity"));

        const titleCell = appendCell(row, "");
        const detailButton = document.createElement("button");
        detailButton.type = "button";
        detailButton.className = "alert-link";
        detailButton.textContent = `${displayValue(alert.title)} · ${displayValue(alert.rule_id)}`;
        detailButton.addEventListener("click", () => showAlertDetails(alert.id));
        titleCell.append(detailButton);

        appendCell(row, alert.ip_address, "mono-cell");
        appendCell(row, alert.username);
        appendCell(row, alert.event_count, "mono-cell");
        appendCell(
            row,
            `${formatTimestamp(alert.window_start)} – ${formatTimestamp(alert.window_end)}`,
            "window-cell",
        );
        const statusCell = appendCell(row, "");
        statusCell.append(badge(alert.status, "status"));
        return row;
    });
    alertsBody.replaceChildren(...(rows.length ? rows : [emptyRow(9, "Noch keine Alarme gespeichert.")]));
    alertCountBadge.textContent = `${alerts.length} geladen`;
    activeAlertCount.textContent = String(
        alerts.filter((alert) => alert.status === "OPEN" || alert.status === "ACKNOWLEDGED").length,
    );
}

function setConnectionState(kind, message) {
    connectionStatus.className = `connection-status is-${kind}`;
    connectionStatus.querySelector("strong").textContent = message;
}

async function requestJson(url) {
    const response = await fetch(url, {cache: "no-store", headers: {Accept: "application/json"}});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
}

function addMetadata(label, value) {
    const term = document.createElement("dt");
    const description = document.createElement("dd");
    term.textContent = label;
    description.textContent = displayValue(value);
    alertMetadata.append(term, description);
}

async function showAlertDetails(alertId) {
    alertDialogTitle.textContent = `Alarm #${alertId}`;
    alertDescription.textContent = "Details werden geladen …";
    alertMetadata.replaceChildren();
    alertEventsBody.replaceChildren();
    alertDialog.showModal();

    try {
        const alert = await requestJson(`/api/alerts/${alertId}`);
        alertDialogTitle.textContent = `${alert.title} · #${alert.id}`;
        alertDescription.textContent = displayValue(alert.description);
        addMetadata("Rule", alert.rule_id);
        addMetadata("Status", alert.status);
        addMetadata("Severity", alert.severity);
        addMetadata("Score", `${alert.score} / 100`);
        addMetadata("IP-Adresse", alert.ip_address);
        addMetadata("Benutzer", alert.username);
        addMetadata("Zeitfenster", `${formatTimestamp(alert.window_start)} – ${formatTimestamp(alert.window_end)}`);
        addMetadata("Aktualisiert", formatTimestamp(alert.updated_at));

        const rows = alert.events.map((event) => {
            const row = document.createElement("tr");
            appendCell(row, formatTimestamp(event.event_timestamp));
            appendCell(row, event.event_type);
            appendCell(row, event.hostname);
            appendCell(row, event.ip_address, "mono-cell");
            appendCell(row, event.username);
            appendCell(row, event.auth_method);
            return row;
        });
        alertEventsBody.replaceChildren(...(rows.length ? rows : [emptyRow(6, "Keine Events verknüpft.")]));
    } catch (error) {
        alertDescription.textContent = `Alarmdetails konnten nicht geladen werden (${error.message}).`;
    }
}

function scheduleRefresh() {
    window.clearTimeout(refreshTimer);
    if (!document.hidden) refreshTimer = window.setTimeout(refreshDashboard, refreshIntervalMs);
}

async function refreshDashboard() {
    if (refreshInProgress || document.hidden) return;
    refreshInProgress = true;
    setConnectionState("loading", "Daten werden aktualisiert");
    try {
        const [events, alerts] = await Promise.all([
            requestJson("/api/events?limit=50"),
            requestJson("/api/alerts?limit=50"),
        ]);
        renderEvents(events);
        renderAlerts(alerts);
        lastUpdated.textContent = formatTimestamp(new Date().toISOString());
        setConnectionState("ok", "Verbunden · Daten aktuell");
    } catch (error) {
        setConnectionState("error", `Aktualisierung fehlgeschlagen · ${error.message}`);
    } finally {
        refreshInProgress = false;
        scheduleRefresh();
    }
}

document.addEventListener("visibilitychange", () => {
    window.clearTimeout(refreshTimer);
    if (!document.hidden) refreshDashboard();
});

refreshDashboard();
