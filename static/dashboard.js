const refreshIntervalMs = 4000;

const connectionStatus = document.querySelector("#connection-status");
const eventCount = document.querySelector("#event-count");
const activeAlertCount = document.querySelector("#active-alert-count");
const lastUpdated = document.querySelector("#last-updated");
const eventCountBadge = document.querySelector("#event-count-badge");
const alertCountBadge = document.querySelector("#alert-count-badge");
const alertStatusFilter = document.querySelector("#alert-status-filter");
const eventsBody = document.querySelector("#events-body");
const alertsBody = document.querySelector("#alerts-body");
const alertDialog = document.querySelector("#alert-dialog");
const alertDialogTitle = document.querySelector("#alert-dialog-title");
const alertDescription = document.querySelector("#alert-description");
const alertMetadata = document.querySelector("#alert-metadata");
const alertEventsBody = document.querySelector("#alert-events-body");
const alertEditForm = document.querySelector("#alert-edit-form");
const alertStatus = document.querySelector("#alert-status");
const alertNote = document.querySelector("#alert-note");
const alertSave = document.querySelector("#alert-save");
const alertCancel = document.querySelector("#alert-cancel");
const alertSaveMessage = document.querySelector("#alert-save-message");

let refreshTimer = null;
let refreshInProgress = false;
let refreshRequested = false;
let saveInProgress = false;
let loadedAlerts = [];
let currentAlert = null;
let alertDataRevision = 0;

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
    loadedAlerts = alerts;
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

async function requestJson(url, options = {}) {
    const response = await fetch(url, {
        ...options,
        cache: "no-store",
        headers: {Accept: "application/json", ...(options.headers || {})},
    });
    if (!response.ok) {
        let message = `HTTP ${response.status}`;
        try {
            const payload = await response.json();
            if (typeof payload.detail === "string") message = payload.detail;
        } catch {
            // Die HTTP-Statusmeldung bleibt als sichere Fallback-Ausgabe erhalten.
        }
        throw new Error(message);
    }
    return response.json();
}

function addMetadata(label, value) {
    const term = document.createElement("dt");
    const description = document.createElement("dd");
    term.textContent = label;
    description.textContent = displayValue(value);
    alertMetadata.append(term, description);
}

function setEditorDisabled(disabled) {
    alertStatus.disabled = disabled;
    alertNote.disabled = disabled;
    alertSave.disabled = disabled;
}

function setSaveMessage(kind, message) {
    alertSaveMessage.className = kind ? `save-message is-${kind}` : "save-message";
    alertSaveMessage.textContent = message;
}

function renderAlertDetails(alert) {
    currentAlert = alert;
    alertDialogTitle.textContent = `${alert.title} · #${alert.id}`;
    alertDescription.textContent = displayValue(alert.description);
    alertMetadata.replaceChildren();
    addMetadata("Rule", alert.rule_id);
    addMetadata("Status", alert.status);
    addMetadata("Severity", alert.severity);
    addMetadata("Score", `${alert.score} / 100`);
    addMetadata("IP-Adresse", alert.ip_address);
    addMetadata("Benutzer", alert.username);
    addMetadata("Zeitfenster", `${formatTimestamp(alert.window_start)} – ${formatTimestamp(alert.window_end)}`);
    addMetadata("Aktualisiert", formatTimestamp(alert.updated_at));

    alertStatus.value = alert.status;
    alertNote.value = alert.note ?? "";
    setEditorDisabled(false);

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
}

async function showAlertDetails(alertId) {
    currentAlert = null;
    alertDialogTitle.textContent = `Alarm #${alertId}`;
    alertDescription.textContent = "Details werden geladen …";
    alertMetadata.replaceChildren();
    alertEventsBody.replaceChildren();
    alertStatus.value = "OPEN";
    alertNote.value = "";
    setSaveMessage("", "");
    setEditorDisabled(true);
    alertDialog.showModal();

    try {
        const alert = await requestJson(`/api/alerts/${alertId}`);
        renderAlertDetails(alert);
    } catch (error) {
        alertDescription.textContent = `Alarmdetails konnten nicht geladen werden (${error.message}).`;
    }
}

function updateRenderedAlert(updatedAlert) {
    const selectedStatus = alertStatusFilter.value;
    const matchesFilter = !selectedStatus || updatedAlert.status === selectedStatus;
    const alerts = loadedAlerts.filter((alert) => alert.id !== updatedAlert.id);
    if (matchesFilter) {
        const originalIndex = loadedAlerts.findIndex((alert) => alert.id === updatedAlert.id);
        const targetIndex = originalIndex < 0 ? 0 : originalIndex;
        alerts.splice(targetIndex, 0, updatedAlert);
    }
    renderAlerts(alerts);
}

async function saveAlertChanges(event) {
    event.preventDefault();
    if (saveInProgress || currentAlert === null) return;

    saveInProgress = true;
    setEditorDisabled(true);
    setSaveMessage("", "Änderungen werden gespeichert …");
    try {
        const updatedAlert = await requestJson(`/api/alerts/${currentAlert.id}`, {
            method: "PATCH",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({status: alertStatus.value, note: alertNote.value}),
        });
        alertDataRevision += 1;
        if (refreshInProgress) refreshRequested = true;
        renderAlertDetails(updatedAlert);
        updateRenderedAlert(updatedAlert);
        setSaveMessage("success", "Status und Notiz wurden gespeichert.");
    } catch (error) {
        setEditorDisabled(false);
        setSaveMessage("error", `Speichern fehlgeschlagen: ${error.message}`);
    } finally {
        saveInProgress = false;
    }
}

function alertListUrl() {
    const parameters = new URLSearchParams({limit: "50"});
    if (alertStatusFilter.value) parameters.set("status", alertStatusFilter.value);
    return `/api/alerts?${parameters.toString()}`;
}

function scheduleRefresh() {
    window.clearTimeout(refreshTimer);
    if (!document.hidden) refreshTimer = window.setTimeout(refreshDashboard, refreshIntervalMs);
}

function requestRefresh() {
    if (refreshInProgress) {
        refreshRequested = true;
        return;
    }
    refreshDashboard();
}

async function refreshDashboard() {
    if (refreshInProgress || document.hidden) return;
    refreshInProgress = true;
    const requestedAlertUrl = alertListUrl();
    const requestedAlertRevision = alertDataRevision;
    setConnectionState("loading", "Daten werden aktualisiert");
    try {
        const [events, alerts] = await Promise.all([
            requestJson("/api/events?limit=50"),
            requestJson(requestedAlertUrl),
        ]);
        renderEvents(events);
        if (
            requestedAlertUrl === alertListUrl()
            && requestedAlertRevision === alertDataRevision
        ) {
            renderAlerts(alerts);
        } else {
            refreshRequested = true;
        }
        lastUpdated.textContent = formatTimestamp(new Date().toISOString());
        setConnectionState("ok", "Verbunden · Daten aktuell");
    } catch (error) {
        setConnectionState("error", `Aktualisierung fehlgeschlagen · ${error.message}`);
    } finally {
        refreshInProgress = false;
        if (refreshRequested && !document.hidden) {
            refreshRequested = false;
            refreshDashboard();
        } else {
            scheduleRefresh();
        }
    }
}

alertEditForm.addEventListener("submit", saveAlertChanges);
alertCancel.addEventListener("click", () => alertDialog.close());
alertStatusFilter.addEventListener("change", () => {
    window.clearTimeout(refreshTimer);
    requestRefresh();
});
document.addEventListener("visibilitychange", () => {
    window.clearTimeout(refreshTimer);
    if (!document.hidden) requestRefresh();
});

refreshDashboard();
