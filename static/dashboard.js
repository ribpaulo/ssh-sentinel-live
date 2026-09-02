const refreshIntervalMs = 4000;

const connectionStatus = document.querySelector("#connection-status");
const eventCount = document.querySelector("#event-count");
const activeAlertCount = document.querySelector("#active-alert-count");
const lastUpdated = document.querySelector("#last-updated");
const monitoringState = document.querySelector("#monitoring-state");
const monitoringDetail = document.querySelector("#monitoring-detail");
const monitoringLastEvent = document.querySelector("#monitoring-last-event");
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
let systemStatusLoaded = false;

function displayValue(value) {
    return value === null || value === undefined || value === "" ? "—" : String(value);
}

function formatTimestamp(value) {
    if (!value) return "—";
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return String(value);
    return new Intl.DateTimeFormat("en-GB", {
        dateStyle: "short",
        timeStyle: "medium",
    }).format(parsed);
}

function formatTimeWindow(start, end) {
    if (!start && !end) return "—";
    if (!start) return formatTimestamp(end);
    if (!end) return formatTimestamp(start);
    return `${formatTimestamp(start)} – ${formatTimestamp(end)}`;
}

function appendElementCell(row) {
    const cell = document.createElement("td");
    row.append(cell);
    return cell;
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

function appendBadgeCell(row, value, kind) {
    if (value === null || value === undefined || value === "") {
        return appendCell(row, null);
    }
    const cell = appendElementCell(row);
    cell.append(badge(value, kind));
    return cell;
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
        appendBadgeCell(row, event.event_type, "event");
        appendCell(row, event.hostname);
        appendCell(row, event.ip_address, "mono-cell");
        appendCell(row, event.username);
        appendCell(row, event.auth_method);
        appendCell(row, event.source, "source-cell");
        return row;
    });
    eventsBody.replaceChildren(...(rows.length ? rows : [emptyRow(7, "No SSH events stored yet.")]));
    eventCount.textContent = String(events.length);
    eventCountBadge.textContent = `${events.length} loaded`;
}

function renderAlerts(alerts) {
    loadedAlerts = alerts;
    const rows = alerts.map((alert) => {
        const row = document.createElement("tr");
        appendCell(row, alert.id, "mono-cell");
        appendCell(row, formatTimestamp(alert.created_at), "timestamp-cell");
        appendBadgeCell(row, alert.severity, "severity");

        const titleCell = appendElementCell(row);
        const detailButton = document.createElement("button");
        detailButton.type = "button";
        detailButton.className = "alert-link";
        if (alert.title || alert.rule_id) {
            if (alert.title) {
                const title = document.createElement("span");
                title.className = "alert-link-title";
                title.textContent = String(alert.title);
                detailButton.append(title);
            }
            if (alert.rule_id) {
                const rule = document.createElement("small");
                rule.className = "alert-link-rule";
                rule.textContent = String(alert.rule_id);
                detailButton.append(rule);
            }
            detailButton.addEventListener("click", () => showAlertDetails(alert.id));
            titleCell.append(detailButton);
        } else {
            titleCell.textContent = "—";
        }

        appendCell(row, alert.ip_address, "mono-cell");
        appendCell(row, alert.username);
        appendCell(row, alert.event_count, "mono-cell");
        appendCell(
            row,
            formatTimeWindow(alert.window_start, alert.window_end),
            "window-cell",
        );
        appendBadgeCell(row, alert.status, "status");
        return row;
    });
    alertsBody.replaceChildren(...(rows.length ? rows : [emptyRow(9, "No alerts stored yet.")]));
    alertCountBadge.textContent = `${alerts.length} loaded`;
    activeAlertCount.textContent = String(
        alerts.filter((alert) => alert.status === "OPEN" || alert.status === "ACKNOWLEDGED").length,
    );
}

function setConnectionState(kind, message) {
    connectionStatus.className = `connection-status is-${kind}`;
    connectionStatus.querySelector("strong").textContent = message;
}

function renderSystemStatus(status) {
    systemStatusLoaded = true;
    const stateLabels = {active: "ACTIVE", inactive: "INACTIVE", error: "ERROR"};
    monitoringState.className = `metric-status is-${status.live_ingestion}`;
    monitoringState.textContent = stateLabels[status.live_ingestion] || displayValue(status.live_ingestion);

    if (!status.database_ready) {
        monitoringDetail.textContent = "The SQLite database is currently unavailable.";
    } else if (status.live_ingestion === "active") {
        monitoringDetail.textContent = `Monitoring: ${displayValue(status.log_file)}`;
    } else if (status.live_ingestion === "error") {
        monitoringDetail.textContent = status.last_error || "Live ingestion has failed.";
    } else {
        monitoringDetail.textContent = "The app is running without integrated live ingestion.";
    }

    if (status.last_event_id === null && !status.last_event_at) {
        monitoringLastEvent.textContent = "Last stored event: —";
    } else {
        const eventParts = [];
        if (status.last_event_id !== null) eventParts.push(`#${status.last_event_id}`);
        if (status.last_event_at) eventParts.push(formatTimestamp(status.last_event_at));
        monitoringLastEvent.textContent = `Last stored event: ${eventParts.join(" · ")}`;
    }
}

function reportSystemStatusError(error) {
    if (!systemStatusLoaded) {
        monitoringState.className = "metric-status is-error";
        monitoringState.textContent = "UNKNOWN";
    }
    monitoringDetail.textContent = `System status temporarily unavailable: ${error.message}`;
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
            // Keep the HTTP status message as a safe fallback.
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
    addMetadata("IP address", alert.ip_address);
    addMetadata("Username", alert.username);
    addMetadata("Time window", formatTimeWindow(alert.window_start, alert.window_end));
    addMetadata("Updated", formatTimestamp(alert.updated_at));

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
    alertEventsBody.replaceChildren(...(rows.length ? rows : [emptyRow(6, "No linked events.")]));
}

async function showAlertDetails(alertId) {
    currentAlert = null;
    alertDialogTitle.textContent = `Alert #${alertId}`;
    alertDescription.textContent = "Loading details …";
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
        alertDescription.textContent = `Alert details could not be loaded (${error.message}).`;
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
    setSaveMessage("", "Saving changes …");
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
        setSaveMessage("success", "Status and note saved.");
    } catch (error) {
        setEditorDisabled(false);
        setSaveMessage("error", `Save failed: ${error.message}`);
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
    setConnectionState("loading", "Updating data");
    const statusRequest = requestJson("/api/system/status")
        .then(renderSystemStatus)
        .catch(reportSystemStatusError);
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
        setConnectionState("ok", "Connected · data current");
    } catch (error) {
        setConnectionState("error", `Update failed · ${error.message}`);
    } finally {
        await statusRequest;
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
