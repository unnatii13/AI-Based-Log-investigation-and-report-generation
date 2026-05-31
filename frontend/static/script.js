const sampleLogs = `Jan 10 10:12:44 firewall sshd[2188]: Failed password for admin from 192.168.1.44 port 51422 ssh2
Jan 10 10:13:01 web01 nginx: 203.0.113.10 GET /login.php 500 SQL injection attempt detected
Jan 10 10:14:27 endpoint01 kernel: USB storage mounted by user analyst
Jan 10 10:15:52 vpn01 auth: Accepted password for manager from 10.0.0.15 port 443
Jan 10 10:16:34 db01 audit: critical privilege escalation attempt from 198.51.100.23`;

const scenarioOneLogs = `2026-05-18 09:02:11 WIN-ORG-07 Security EventID=4624 Account Name=rahul SourceNetworkAddress=10.20.4.55 Logon Type=2 Interactive logon successful
2026-05-18 09:07:42 WIN-ORG-07 FileAudit user=rahul opened C:\\Finance\\Q4_confidential_client_list.xlsx
2026-05-18 09:09:18 WIN-ORG-07 FileAudit user=rahul copied C:\\Finance\\Q4_confidential_client_list.xlsx to C:\\Users\\rahul\\Desktop\\client_list_copy.xlsx
2026-05-18 09:11:03 WIN-ORG-07 Kernel-PnP USB device connected VID_18D1 PID_4EE7 serial=ANDROID-73K9 MTP removable device Android phone
2026-05-18 09:12:27 WIN-ORG-07 MTPTransfer user=rahul copied C:\\Users\\rahul\\Desktop\\client_list_copy.xlsx to Android device serial=ANDROID-73K9 path=/sdcard/Download/client_list_copy.xlsx channel=USB
2026-05-18 09:15:09 ANDROID-73K9 MediaProvider file=/sdcard/Download/client_list_copy.xlsx opened by app=com.google.android.apps.docs user=rahul
2026-05-18 09:17:44 ANDROID-73K9 Bluetooth OBEX transfer sent /sdcard/Download/client_list_copy.xlsx to device=OnePlus-Nord channel=Bluetooth
2026-05-18 09:21:36 ANDROID-73K9 Gmail app=Gmail user=rahul sent email to external.receiver@example.com attachment=/sdcard/Download/client_list_copy.xlsx source_ip=10.20.4.92
2026-05-18 09:21:41 firewall01 allow TCP SRC=10.20.4.92 DST=142.250.195.37 DPT=587 SMTP mail upload attachment client_list_copy.xlsx
2026-05-18 09:24:13 WIN-ORG-07 Security EventID=4634 Account Name=rahul Logoff completed`;

const scenarioTwoLogs = `2026-05-19 14:03:18 WIN-FIN-12 browser.exe user=meena downloaded http://updates-secure.example/download/invoice_viewer.exe to C:\\Users\\meena\\Downloads\\invoice_viewer.exe source_ip=203.0.113.77
2026-05-19 14:04:02 WIN-FIN-12 host_ip=10.20.6.44 Security EventID=4688 Account Name=meena New Process Created Process Command Line: C:\\Users\\meena\\Downloads\\invoice_viewer.exe
2026-05-19 14:04:37 WIN-FIN-12 host_ip=10.20.6.44 Security EventID=4688 Account Name=meena New Process Created Process Command Line: powershell.exe -EncodedCommand SQBFAFgA suspicious payload execution
2026-05-19 14:05:08 WIN-FIN-12 host_ip=10.20.6.44 Defender CRITICAL malware ransomware payload detected process=invoice_viewer.exe file=C:\\Users\\meena\\AppData\\Roaming\\svchost32.exe
2026-05-19 14:05:44 WIN-FIN-12 host_ip=10.20.6.44 Security EventID=4688 Account Name=meena New Process Created Process Command Line: vssadmin.exe delete shadows /all /quiet shadow copy deletion
2026-05-19 14:06:21 WIN-FIN-12 host_ip=10.20.6.44 FileAudit ransomware encrypted C:\\Finance\\payroll.xlsx to C:\\Finance\\payroll.xlsx.locked
2026-05-19 14:06:48 WIN-FIN-12 host_ip=10.20.6.44 FileAudit ransomware encrypted C:\\Finance\\vendor_payments.pdf to C:\\Finance\\vendor_payments.pdf.locked
2026-05-19 14:07:13 WIN-FIN-12 host_ip=10.20.6.44 FileAudit ransomware encrypted C:\\HR\\employee_records.csv to C:\\HR\\employee_records.csv.locked
2026-05-19 14:08:02 WIN-FIN-12 host_ip=10.20.6.44 Application ERROR ransom_note.txt created at C:\\Users\\Public\\README_RECOVER_FILES.txt
2026-05-19 14:09:29 firewall01 block TCP SRC=10.20.6.44 DST=198.51.100.88 DPT=443 ransomware command and control beacon denied`;

const state = {
    summary: {},
    events: [],
    timeline: [],
    charts: {},
    cases: [],
    activeCaseId: null,
};

const $ = (id) => document.getElementById(id);

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;",
    })[char]);
}

function setMessage(text, type = "info") {
    const box = $("messageBox");
    box.textContent = text;
    box.dataset.type = type;
}

function setBusy(isBusy, text = "Working") {
    $("modelStatus").textContent = isBusy ? text : "Ready";
    $("analyzeBtn").disabled = isBusy;
}

function filtersAsParams() {
    const params = new URLSearchParams();
    const pairs = {
        search: $("searchFilter").value.trim(),
        verdict: $("verdictFilter").value,
        severity: $("severityFilter").value,
        source_ip: $("sourceIpFilter").value.trim(),
        event_type: $("eventTypeFilter").value.trim(),
        limit: "250",
    };

    Object.entries(pairs).forEach(([key, value]) => {
        if (value) params.set(key, value);
    });

    return params;
}

async function requestJson(url, options = {}) {
    const csrfToken = document.body.dataset.csrfToken;
    const method = (options.method || "GET").toUpperCase();
    if (csrfToken && !["GET", "HEAD", "OPTIONS"].includes(method)) {
        const headers = new Headers(options.headers || {});
        headers.set("X-CSRF-Token", csrfToken);
        options.headers = headers;
    }

    const response = await fetch(url, options);
    const payload = await response.json().catch(() => ({}));

    if (!response.ok) {
        throw new Error(payload.error || `Request failed with ${response.status}`);
    }

    return payload;
}

function selectedCaseId() {
    return state.activeCaseId || $("caseSelect").value;
}

function requireSelectedCase() {
    const caseId = selectedCaseId();
    if (!caseId) {
        throw new Error("Create or select a case first.");
    }
    return caseId;
}

function selectedLogType() {
    return $("logTypeSelect").value || "generic";
}

function renderCases() {
    const select = $("caseSelect");

    if (!state.cases.length) {
        select.innerHTML = '<option value="">No cases yet</option>';
        state.activeCaseId = null;
        $("selectedCaseLabel").textContent = "No case selected.";
        return;
    }

    if (!state.activeCaseId || !state.cases.some((item) => String(item.id) === String(state.activeCaseId))) {
        state.activeCaseId = String(state.cases[0].id);
    }

    select.innerHTML = state.cases.map((item) => `
        <option value="${escapeHtml(item.id)}" ${String(item.id) === String(state.activeCaseId) ? "selected" : ""}>
            ${escapeHtml(item.title)} (${escapeHtml(item.log_count || 0)})
        </option>
    `).join("");

    const activeCase = state.cases.find((item) => String(item.id) === String(state.activeCaseId));
    $("selectedCaseLabel").textContent = activeCase
        ? `Selected case #${activeCase.id}: ${activeCase.title}`
        : "No case selected.";
}

async function loadCases() {
    const data = await requestJson("/cases");
    state.cases = data.cases || [];
    renderCases();
}

async function createCase() {
    const title = $("newCaseName").value.trim();
    if (!title) {
        setMessage("Enter a case name before creating a case.", "warning");
        return;
    }

    try {
        const data = await requestJson("/cases", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ title }),
        });
        $("newCaseName").value = "";
        await loadCases();
        state.activeCaseId = String(data.case.id);
        renderCases();
        await refreshResults();
        await refreshTimeline();
        setMessage(`Case "${data.case.title}" created.`, "success");
    } catch (error) {
        setMessage(error.message, "error");
    }
}

function updateStats(summary = {}) {
    $("totalLogs").textContent = summary.total_logs || 0;
    $("alerts").textContent = summary.alerts || 0;
    $("attacks").textContent = summary.attacks || 0;
    $("averageRisk").textContent = summary.average_risk || 0;
    drawVerticalBarChart("verdictChart", summary.verdict_counts || {}, ["#b94a5a", "#c58a35", "#3a8f7b"]);
    drawVerticalBarChart("ipChart", summary.top_ips || {}, ["#3a8f7b", "#6e7f94", "#a7834a", "#8b6478", "#4f786c"]);
}

function verdictClass(verdict = "") {
    return verdict.toLowerCase().replace(/[^a-z0-9]+/g, "-");
}

function renderEvents(events = []) {
    const tbody = $("eventsBody");

    if (!events.length) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No matching events found.</td></tr>';
        return;
    }

    tbody.innerHTML = events.map((event) => `
        <tr>
            <td>${escapeHtml(event.line_no)}</td>
            <td>${escapeHtml(event.timestamp || "unknown")}</td>
            <td>${escapeHtml(event.source_ip || "unknown")}</td>
            <td><span class="severity">${escapeHtml(event.severity || "low")}</span></td>
            <td>${escapeHtml(event.event_type || "unknown")}</td>
            <td>${escapeHtml(event.risk_score ?? 0)}</td>
            <td><span class="verdict ${verdictClass(event.verdict)}">${escapeHtml(event.verdict || "NORMAL")}</span></td>
            <td>${escapeHtml(event.explanation || "")}</td>
        </tr>
    `).join("");
}

function drawVerticalBarChart(canvasId, values, palette) {
    const canvas = $(canvasId);
    const context = canvas.getContext("2d");
    const entries = Object.entries(values).slice(0, 8);
    const width = canvas.width;
    const height = canvas.height;
    const padding = { top: 28, right: 22, bottom: 66, left: 42 };
    const plotWidth = width - padding.left - padding.right;
    const plotHeight = height - padding.top - padding.bottom;

    context.clearRect(0, 0, width, height);
    state.charts[canvasId] = [];

    if (!entries.length) {
        context.fillStyle = "#768293";
        context.font = "14px Arial";
        context.fillText("No data yet", 24, 42);
        return;
    }

    const max = Math.max(...entries.map(([, value]) => Number(value)), 1);
    const slotWidth = plotWidth / entries.length;
    const barWidth = Math.min(58, slotWidth * 0.58);

    context.strokeStyle = "#354253";
    context.lineWidth = 1;
    context.beginPath();
    context.moveTo(padding.left, padding.top);
    context.lineTo(padding.left, padding.top + plotHeight);
    context.lineTo(width - padding.right, padding.top + plotHeight);
    context.stroke();

    entries.forEach(([label, value], index) => {
        const numericValue = Number(value);
        const barHeight = Math.max(4, (plotHeight * numericValue) / max);
        const x = padding.left + index * slotWidth + (slotWidth - barWidth) / 2;
        const y = padding.top + plotHeight - barHeight;
        const color = palette[index % palette.length];

        const gradient = context.createLinearGradient(0, y, 0, y + barHeight);
        gradient.addColorStop(0, color);
        gradient.addColorStop(1, `${color}b8`);

        context.fillStyle = gradient;
        context.beginPath();
        context.roundRect(x, y, barWidth, barHeight, 8);
        context.fill();

        context.fillStyle = "#dbe4ef";
        context.font = "bold 13px Arial";
        context.textAlign = "center";
        context.fillText(numericValue, x + barWidth / 2, y - 8);

        context.save();
        context.translate(x + barWidth / 2, height - 12);
        context.rotate(-Math.PI / 7);
        context.font = "12px Arial";
        context.fillStyle = "#92a0b2";
        context.fillText(String(label).slice(0, 14), 0, 0);
        context.restore();

        state.charts[canvasId].push({
            x,
            y,
            width: barWidth,
            height: barHeight,
            label,
            value: numericValue,
        });
    });

    context.textAlign = "left";
}

async function refreshResults() {
    const caseId = requireSelectedCase();
    const params = filtersAsParams();
    const data = await requestJson(`/cases/${caseId}/results?${params.toString()}`);
    state.summary = data.summary || {};
    state.events = data.events || [];
    updateStats(state.summary);
    renderEvents(state.events);
}

async function refreshTimeline() {
    const caseId = requireSelectedCase();
    const data = await requestJson(`/cases/${caseId}/timeline`);
    state.timeline = data.timeline || [];
    renderTimeline(data);
}

async function analyzeLogs() {
    const logs = $("logInput").value.trim();
    let caseId;

    if (!logs) {
        setMessage("Paste logs or upload a file before analysis.", "warning");
        return;
    }

    try {
        caseId = requireSelectedCase();
    } catch (error) {
        setMessage(error.message, "warning");
        return;
    }

    setBusy(true, "Analyzing");
    setMessage("Analyzing evidence and storing results...");

    try {
        const data = await requestJson(`/cases/${caseId}/upload_logs`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ logs, log_type: selectedLogType() }),
        });

        updateStats(data.summary);
        renderEvents(data.events || []);
        await loadCases();
        await refreshTimeline();
        setMessage(`Processed ${data.summary.total_logs || 0} log entries.`, "success");
    } catch (error) {
        setMessage(error.message, "error");
    } finally {
        setBusy(false);
    }
}

async function uploadFile(file) {
    let caseId;
    try {
        caseId = requireSelectedCase();
    } catch (error) {
        setMessage(error.message, "warning");
        $("fileInput").value = "";
        return;
    }

    const formData = new FormData();
    formData.append("file", file);
    formData.append("log_type", selectedLogType());

    setBusy(true, "Uploading");
    setMessage(`Uploading ${file.name}...`);

    try {
        const data = await requestJson(`/cases/${caseId}/upload_file`, {
            method: "POST",
            body: formData,
        });

        updateStats(data.summary);
        renderEvents(data.events || []);
        await loadCases();
        await refreshTimeline();
        setMessage(`Uploaded and processed ${file.name}.`, "success");
    } catch (error) {
        setMessage(error.message, "error");
    } finally {
        setBusy(false);
        $("fileInput").value = "";
    }
}

async function clearLogs() {
    let caseId;
    try {
        caseId = requireSelectedCase();
    } catch (error) {
        setMessage(error.message, "warning");
        return;
    }

    const confirmed = window.confirm("Clear logs for the selected case?");
    if (!confirmed) return;

    setBusy(true, "Clearing");

    try {
        await requestJson(`/cases/${caseId}/logs`, { method: "DELETE" });
        state.summary = {};
        state.events = [];
        updateStats(state.summary);
        renderEvents(state.events);
        renderTimeline({});
        await loadCases();
        setMessage("Stored logs cleared.", "success");
    } catch (error) {
        setMessage(error.message, "error");
    } finally {
        setBusy(false);
    }
}

async function verifyChain() {
    let caseId;
    try {
        caseId = requireSelectedCase();
    } catch (error) {
        setMessage(error.message, "warning");
        return;
    }

    try {
        const data = await requestJson(`/cases/${caseId}/verify_chain`);
        if (data.valid) {
            setMessage(`Chain verified for ${data.checked_logs || 0} logs.`, "success");
            return;
        }
        setMessage(`Chain verification failed for ${data.failures.length} log(s).`, "error");
    } catch (error) {
        setMessage(error.message, "error");
    }
}

function exportReport(type) {
    const caseId = requireSelectedCase();
    const params = filtersAsParams();
    window.location.href = `/cases/${caseId}/export/${type}?${params.toString()}`;
}

function exportIntegration(target) {
    const caseId = requireSelectedCase();
    const params = filtersAsParams();
    window.location.href = `/cases/${caseId}/integrations/export/${target}?${params.toString()}`;
}

async function refreshIntegrationStatus() {
    const caseId = requireSelectedCase();
    const data = await requestJson(`/cases/${caseId}/integrations`);
    const targets = data.push_targets || {};
    const elasticStatus = targets.elastic?.configured ? "configured" : "not configured";
    const splunkStatus = targets.splunk?.configured ? "configured" : "not configured";
    $("integrationStatus").textContent = `Exports are available offline. Push status: Elastic/OpenSearch ${elasticStatus}, Splunk ${splunkStatus}.`;
}

async function pushIntegration(target) {
    const caseId = requireSelectedCase();
    setBusy(true, `Pushing ${target}`);
    try {
        const result = await requestJson(`/cases/${caseId}/integrations/push/${target}`, { method: "POST" });
        $("integrationStatus").textContent = `${target} push ${result.ok ? "succeeded" : "failed"} with status ${result.status_code}.`;
        setMessage(`${target} push completed.`, result.ok ? "success" : "warning");
    } catch (error) {
        $("integrationStatus").textContent = error.message;
        setMessage(error.message, "error");
    } finally {
        setBusy(false);
    }
}

function renderTimeline(data = {}) {
    const summary = $("timelineSummary");
    const list = $("timelineList");
    const timeline = data.timeline || [];

    summary.textContent = data.summary || "No timeline available for this case yet.";
    renderEntityStrip(data.entities || {});

    if (!timeline.length) {
        list.innerHTML = '<div class="empty-state">No timeline events yet.</div>';
        return;
    }

    list.innerHTML = timeline.map((item) => `
        <article class="timeline-item ${verdictClass(item.verdict)}">
            <div class="timeline-marker"></div>
            <div class="timeline-content">
                <div class="timeline-topline">
                    <strong>${escapeHtml(item.phase)}</strong>
                    <span>${escapeHtml(item.time)}</span>
                </div>
                <div class="timeline-meta">
                    <span>${escapeHtml(item.verdict)}</span>
                    <span>Risk ${escapeHtml(item.risk_score)}%</span>
                    <span>Confidence ${escapeHtml(item.confidence)}%</span>
                    <span>${escapeHtml(item.source_ip)}</span>
                </div>
                ${renderEvidencePills(item)}
                <p>${escapeHtml(item.raw_log)}</p>
            </div>
        </article>
    `).join("");
}

function renderEntityStrip(entities) {
    const entityStrip = $("entityStrip");
    const entries = Object.entries(entities).flatMap(([key, values]) => (
        Object.entries(values || {}).slice(0, 4).map(([value, count]) => ({ key, value, count }))
    )).slice(0, 18);

    entityStrip.innerHTML = entries.length
        ? entries.map((entry) => `<span><b>${escapeHtml(entry.key)}</b>${escapeHtml(entry.value)} (${escapeHtml(entry.count)})</span>`).join("")
        : "";
}

function renderEvidencePills(item) {
    const values = [
        ...(item.users || []).map((value) => `user: ${value}`),
        ...(item.hosts || []).map((value) => `host: ${value}`),
        ...(item.files || []).map((value) => `file: ${value}`),
        ...(item.channels || []).map((value) => `channel: ${value}`),
        ...(item.ips || []).map((value) => `ip: ${value}`),
        ...(item.processes || []).map((value) => `process: ${value}`),
        ...(item.emails || []).map((value) => `email: ${value}`),
        ...(item.apps || []).map((value) => `app: ${value}`),
    ].slice(0, 8);

    if (!values.length) return "";
    return `<div class="evidence-pills">${values.map((value) => `<span>${escapeHtml(value)}</span>`).join("")}</div>`;
}

async function askCase() {
    const question = $("caseQuestion").value.trim();
    let caseId;

    if (!question) {
        setMessage("Enter a question for the selected case.", "warning");
        return;
    }

    try {
        caseId = requireSelectedCase();
    } catch (error) {
        setMessage(error.message, "warning");
        return;
    }

    setBusy(true, "Querying");
    try {
        const data = await requestJson(`/cases/${caseId}/ask`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ query: question }),
        });
        const intentLabel = data.intent ? ` Intent: ${data.intent.replace(/_/g, " ")}.` : "";
        const confidenceLabel = data.confidence ? ` Confidence: ${data.confidence}%.` : "";
        const mitreLabel = Array.isArray(data.mitre) && data.mitre.length
            ? ` MITRE: ${data.mitre.map((item) => `${item.technique_id} ${item.name}`).join("; ")}.`
            : "";
        $("answerBox").textContent = `${data.answer} Evidence events: ${data.matched_count || 0}.${intentLabel}${confidenceLabel}${mitreLabel}`;
        $("queryResults").innerHTML = (data.events || []).slice(0, 8).map((item) => `
            <article>
                <strong>${escapeHtml(item.phase)}</strong>
                <span>${escapeHtml(item.time)} | ${escapeHtml(item.verdict)} | ${escapeHtml(item.source_ip)}</span>
                <p>${escapeHtml(item.raw_log)}</p>
            </article>
        `).join("") || '<div class="empty-state">No matching events found.</div>';
    } catch (error) {
        $("answerBox").textContent = error.message;
    } finally {
        setBusy(false);
    }
}

function debounce(fn, delay = 300) {
    let timer;
    return (...args) => {
        clearTimeout(timer);
        timer = setTimeout(() => fn(...args), delay);
    };
}

function bindEvents() {
    $("createCaseBtn").addEventListener("click", createCase);
    $("caseSelect").addEventListener("change", () => {
        state.activeCaseId = $("caseSelect").value;
        renderCases();
        refreshResults()
            .then(refreshTimeline)
            .catch((error) => setMessage(error.message, "error"));
    });
    $("analyzeBtn").addEventListener("click", analyzeLogs);
    $("loadSampleBtn").addEventListener("click", () => {
        $("logInput").value = sampleLogs;
        setMessage("Sample logs loaded.", "success");
    });
    $("loadScenarioOneBtn").addEventListener("click", () => {
        $("logInput").value = scenarioOneLogs;
        $("logTypeSelect").value = "endpoint";
        setMessage("Scenario 1 data-transfer logs loaded.", "success");
    });
    $("loadScenarioTwoBtn").addEventListener("click", () => {
        $("logInput").value = scenarioTwoLogs;
        $("logTypeSelect").value = "endpoint";
        setMessage("Scenario 2 ransomware logs loaded.", "success");
    });
    $("fileInput").addEventListener("change", (event) => {
        const [file] = event.target.files;
        if (file) uploadFile(file);
    });
    $("clearBtn").addEventListener("click", clearLogs);
    $("verifyChainBtn").addEventListener("click", verifyChain);
    $("refreshBtn").addEventListener("click", () => refreshResults().catch((error) => setMessage(error.message, "error")));
    $("refreshTimelineBtn").addEventListener("click", () => refreshTimeline().catch((error) => setMessage(error.message, "error")));
    $("refreshIntegrationBtn").addEventListener("click", () => refreshIntegrationStatus().catch((error) => setMessage(error.message, "error")));
    $("askCaseBtn").addEventListener("click", askCase);
    $("caseQuestion").addEventListener("keydown", (event) => {
        if (event.key === "Enter") askCase();
    });

    document.querySelectorAll("[data-export]").forEach((button) => {
        button.addEventListener("click", () => {
            try {
                exportReport(button.dataset.export);
            } catch (error) {
                setMessage(error.message, "warning");
            }
        });
    });

    document.querySelectorAll("[data-integration-export]").forEach((button) => {
        button.addEventListener("click", () => {
            try {
                exportIntegration(button.dataset.integrationExport);
            } catch (error) {
                setMessage(error.message, "warning");
            }
        });
    });

    document.querySelectorAll("[data-integration-push]").forEach((button) => {
        button.addEventListener("click", () => pushIntegration(button.dataset.integrationPush));
    });

    const autoRefresh = debounce(() => refreshResults().catch((error) => setMessage(error.message, "error")));
    ["searchFilter", "verdictFilter", "severityFilter", "sourceIpFilter", "eventTypeFilter"].forEach((id) => {
        $(id).addEventListener("input", autoRefresh);
        $(id).addEventListener("change", autoRefresh);
    });

    ["verdictChart", "ipChart"].forEach(bindChartTooltip);
}

document.addEventListener("DOMContentLoaded", () => {
    bindEvents();
    updateStats({});
    renderEvents([]);
    loadCases()
        .then(() => {
            if (state.activeCaseId) {
                return refreshResults()
                    .then(refreshTimeline)
                    .then(refreshIntegrationStatus);
            }
            setMessage("Create a case before starting a new analysis.", "info");
            return null;
        })
        .catch((error) => setMessage(error.message, "error"));
});

function bindChartTooltip(canvasId) {
    const canvas = $(canvasId);
    const tooltip = $(`${canvasId}Tooltip`);

    canvas.addEventListener("mousemove", (event) => {
        const rect = canvas.getBoundingClientRect();
        const scaleX = canvas.width / rect.width;
        const scaleY = canvas.height / rect.height;
        const x = (event.clientX - rect.left) * scaleX;
        const y = (event.clientY - rect.top) * scaleY;
        const hit = (state.charts[canvasId] || []).find((bar) => (
            x >= bar.x &&
            x <= bar.x + bar.width &&
            y >= bar.y &&
            y <= bar.y + bar.height
        ));

        if (!hit) {
            tooltip.classList.remove("visible");
            return;
        }

        tooltip.innerHTML = `<strong>${escapeHtml(hit.label)}</strong><span>Count: ${escapeHtml(hit.value)}</span>`;
        tooltip.style.left = `${event.clientX - rect.left + 14}px`;
        tooltip.style.top = `${event.clientY - rect.top - 12}px`;
        tooltip.classList.add("visible");
    });

    canvas.addEventListener("mouseleave", () => {
        tooltip.classList.remove("visible");
    });
}
