/**
 * main.js
 * Orchestration UI : soumission du formulaire, mise à jour du terminal
 * live pendant le scan, rendu des résultats une fois terminé.
 */
(() => {
    const form = document.getElementById("scanForm");
    const domainInput = document.getElementById("domainInput");
    const providerSelect = document.getElementById("providerSelect");
    const techEngineSelect = document.getElementById("techEngineSelect");
    const scanButton = document.getElementById("scanButton");
    const formError = document.getElementById("formError");

    const terminalSection = document.getElementById("terminalSection");
    const terminalBody = document.getElementById("terminalBody");
    const terminalDomain = document.getElementById("terminalDomain");
    const terminalCmd = document.getElementById("terminalCmd");

    const resultsSection = document.getElementById("resultsSection");
    const scanErrorSection = document.getElementById("scanErrorSection");
    const scanErrorDetail = document.getElementById("scanErrorDetail");

    const gaugeFill = document.getElementById("gaugeFill");
    const gaugeValue = document.getElementById("gaugeValue");
    const scoreBand = document.getElementById("scoreBand");
    const summaryCards = document.getElementById("summaryCards");
    const accordion = document.getElementById("accordion");
    const downloadBtn = document.getElementById("downloadReportBtn");

    const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 60; // r=60 dans le SVG

    const historyList = document.getElementById("historyList");
    const historyRefresh = document.getElementById("historyRefresh");

    // ------------------------------------------------------------
    // Statut API (header)
    // ------------------------------------------------------------
    async function checkApiHealth() {
        const dot = document.getElementById("apiStatusDot");
        const text = document.getElementById("apiStatusText");
        const health = await apiCheckHealth();

        dot.classList.toggle("up", health.up);
        dot.classList.toggle("down", !health.up);

        if (!health.up) {
            text.textContent = "API injoignable";
            return;
        }

        // Signale les outils externes manquants — un scan sans WhatWeb
        // ou theHarvester renvoie des résultats partiels, mieux vaut le
        // savoir avant de lancer plutôt qu'après.
        const missing = Object.entries(health.tools || {})
            .filter(([, present]) => !present)
            .map(([name]) => name);

        text.textContent = missing.length
            ? `API connectée · ${missing.length} outil(s) manquant(s) : ${missing.join(", ")}`
            : "API connectée";
    }
    checkApiHealth();

    // ------------------------------------------------------------
    // Historique
    // ------------------------------------------------------------
    async function loadHistory() {
        historyList.innerHTML = `<p class="history-empty">Chargement de l'historique…</p>`;
        try {
            const { entries } = await apiListScans({ limit: 20 });

            if (!entries.length) {
                historyList.innerHTML = `<p class="history-empty">Aucun scan pour l'instant. Lance-en un pour commencer.</p>`;
                return;
            }

            historyList.innerHTML = entries.map((e) => {
                const date = e.created_at
                    ? new Date(e.created_at).toLocaleString("fr-FR", {
                          day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit",
                      })
                    : "—";
                const score = e.score !== null && e.score !== undefined
                    ? `<span class="history-score band-text-${e.band}">${e.score.toFixed(1)}</span>`
                    : `<span class="history-score">—</span>`;

                return `
                    <div class="history-row" data-id="${escapeHtml(e.id)}">
                        <span class="history-domain">${escapeHtml(e.domain)}</span>
                        <span class="history-date">${escapeHtml(date)}</span>
                        ${score}
                        <span class="history-status status-${escapeHtml(e.status)}">${escapeHtml(e.status)}</span>
                        <span class="history-actions">
                            ${e.status === "done"
                                ? `<a class="icon-btn" href="${apiGetReportUrl(e.id)}" title="Télécharger le rapport PDF">PDF</a>`
                                : ""}
                            <button type="button" class="icon-btn danger" data-action="delete" title="Supprimer ce scan">×</button>
                        </span>
                    </div>
                `;
            }).join("");

            historyList.querySelectorAll('[data-action="delete"]').forEach((btn) => {
                btn.addEventListener("click", async () => {
                    const row = btn.closest(".history-row");
                    const id = row.dataset.id;
                    if (!window.confirm("Supprimer ce scan et son rapport PDF ?")) return;
                    try {
                        await apiDeleteScan(id);
                        loadHistory();
                    } catch (err) {
                        window.alert(`Suppression impossible : ${err.message}`);
                    }
                });
            });
        } catch (err) {
            historyList.innerHTML = `<p class="history-empty">Historique indisponible : ${escapeHtml(err.message)}</p>`;
        }
    }

    historyRefresh.addEventListener("click", loadHistory);
    loadHistory();

    // ------------------------------------------------------------
    // Terminal live
    // ------------------------------------------------------------
    function resetTerminal(domain) {
        terminalDomain.textContent = domain;
        terminalCmd.textContent = `scan ${domain}`;
        // On vide tout sauf la ligne de commande initiale
        terminalBody.innerHTML = `<div class="terminal-line"><span class="prompt">$</span> scan ${escapeHtml(domain)}</div>`;
    }

    const seenProgressLines = new Set();
    function appendTerminalLine(text, variant = "") {
        if (seenProgressLines.has(text)) return;
        seenProgressLines.add(text);

        const line = document.createElement("div");
        line.className = `terminal-line ${variant}`.trim();
        line.textContent = text;
        terminalBody.appendChild(line);
        terminalBody.scrollTop = terminalBody.scrollHeight;
    }

    function appendCursor() {
        const existing = terminalBody.querySelector(".cursor");
        if (existing) existing.remove();
        const cursor = document.createElement("span");
        cursor.className = "cursor";
        const last = terminalBody.lastElementChild;
        (last || terminalBody).appendChild(cursor);
    }

    // ------------------------------------------------------------
    // Soumission du formulaire
    // ------------------------------------------------------------
    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        formError.hidden = true;
        resultsSection.hidden = true;
        scanErrorSection.hidden = true;
        seenProgressLines.clear();

        const domain = domainInput.value.trim().toLowerCase();
        const provider = providerSelect.value;
        const techEngine = techEngineSelect.value;

        scanButton.disabled = true;
        scanButton.querySelector(".btn-scan-text").textContent = "Lancement…";

        terminalSection.hidden = false;
        resetTerminal(domain);
        appendCursor();
        terminalSection.scrollIntoView({ behavior: "smooth", block: "start" });

        try {
            const { id: scanId } = await apiStartScan(domain, provider, techEngine);
            appendTerminalLine(`Scan créé (id: ${scanId.slice(0, 8)}…)`, "step");
            scanButton.querySelector(".btn-scan-text").textContent = "Scan en cours…";

            const finalStatus = await pollScanStatus(scanId, {
                onUpdate: (status) => {
                    if (status.progress) {
                        appendTerminalLine(status.progress, "step");
                    }
                    appendCursor();
                },
            });

            if (finalStatus.status === "done") {
                appendTerminalLine("Scan terminé.", "done");
                const results = await apiGetResults(scanId);
                renderResults(results, scanId);
                resultsSection.hidden = false;
                resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
                loadHistory();
            } else {
                throw new ApiError(500, finalStatus.error || "Le scan a échoué sans message d'erreur.");
            }
        } catch (err) {
            appendTerminalLine(`Erreur : ${err.message}`, "error");
            scanErrorDetail.textContent = err.message;
            scanErrorSection.hidden = false;
            loadHistory();
        } finally {
            scanButton.disabled = false;
            scanButton.querySelector(".btn-scan-text").textContent = "Scanner";
            const cursor = terminalBody.querySelector(".cursor");
            if (cursor) cursor.remove();
        }
    });

    // ------------------------------------------------------------
    // Rendu des résultats
    // ------------------------------------------------------------
    function renderResults(scan, scanId) {
        renderScoreGauge(scan.score, scan.score_details);
        renderSummaryCards(scan);
        renderAccordion(scan);

        downloadBtn.href = apiGetReportUrl(scanId);
        downloadBtn.hidden = false;
        downloadBtn.setAttribute("download", `rapport_${scan.domain}.pdf`);
    }

    function renderScoreGauge(score, scoreDetails) {
        const band = scoreDetails ? scoreDetails.band : "Low";
        const safeScore = score ?? 0;

        gaugeValue.textContent = score !== null && score !== undefined ? score.toFixed(1) : "—";
        scoreBand.textContent = band;
        scoreBand.className = `score-band band-${band}`;
        gaugeFill.className.baseVal = `gauge-fill band-${band}`;

        const offset = GAUGE_CIRCUMFERENCE * (1 - safeScore / 100);
        // Léger délai pour laisser le navigateur peindre l'état initial
        // avant la transition — sinon l'animation ne se joue pas.
        requestAnimationFrame(() => {
            gaugeFill.style.strokeDashoffset = offset;
        });
    }

    function renderSummaryCards(scan) {
        const leaked = scan.leaks.filter((l) => l.leaked).length;
        const totalTechs = scan.technologies.reduce((sum, e) => sum + e.technologies.length, 0);

        const cards = [
            { value: scan.subdomains.length, label: "Sous-domaines actifs" },
            { value: totalTechs, label: "Technologies détectées" },
            { value: scan.employees.length, label: "Employés identifiés" },
            { value: `${leaked}/${scan.leaks.length}`, label: "Emails compromis" },
        ];

        summaryCards.innerHTML = cards.map((c) => `
            <div class="summary-card">
                <div class="value">${c.value}</div>
                <div class="label">${c.label}</div>
            </div>
        `).join("");
    }

    function renderAccordion(scan) {
        const emailSecCount = scan.email_security
            ? [scan.email_security.spf.risk, scan.email_security.dmarc.risk]
                  .filter((r) => r === "high" || r === "critical").length
            : 0;

        const sections = [
            {
                title: "Sous-domaines actifs",
                count: scan.subdomains.length,
                html: renderSubdomainsTable(scan.subdomains),
            },
            {
                title: "Subdomain takeover",
                count: scan.takeover_candidates.filter((c) => c.confidence === "high").length,
                html: renderTakeoverTable(scan.takeover_candidates),
            },
            {
                title: "Environnements hors-prod / panneaux admin",
                count: scan.environment_candidates.filter((c) => c.category === "admin_panel").length,
                html: renderEnvironmentsTable(scan.environment_candidates),
            },
            {
                title: "Technologies détectées",
                count: scan.technologies.reduce((sum, e) => sum + e.technologies.length, 0),
                html: renderTechnologiesTable(scan.technologies),
            },
            {
                title: "Surface de phishing (SPF/DKIM/DMARC)",
                count: emailSecCount,
                html: renderEmailSecurityPanel(scan.email_security),
            },
            {
                title: "Employés identifiés",
                count: scan.employees.length,
                html: renderEmployeesTable(scan.employees),
            },
            {
                title: "Fuites de credentials",
                count: scan.leaks.filter((l) => l.leaked).length,
                html: renderLeaksTable(scan.leaks),
            },
        ];

        accordion.innerHTML = sections.map((s, i) => `
            <div class="accordion-item ${i === 0 ? "open" : ""}" data-index="${i}">
                <button class="accordion-trigger" type="button">
                    <span>${s.title}<span class="count">(${s.count})</span></span>
                    <svg class="accordion-chevron" width="16" height="16" viewBox="0 0 16 16" fill="none">
                        <path d="M4 6l4 4 4-4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </button>
                <div class="accordion-panel">${s.html}</div>
            </div>
        `).join("");

        accordion.querySelectorAll(".accordion-trigger").forEach((btn) => {
            btn.addEventListener("click", () => {
                btn.closest(".accordion-item").classList.toggle("open");
            });
        });
    }

    function renderSubdomainsTable(subdomains) {
        if (!subdomains.length) return emptyPanel("Aucun sous-domaine actif détecté.");
        const rows = subdomains.map((s) => `
            <tr><td>${escapeHtml(s.subdomain)}</td><td>${escapeHtml(s.ips.join(", ") || "—")}</td></tr>
        `).join("");
        return `<table class="data-table">
            <thead><tr><th>Sous-domaine</th><th>Adresse(s) IP</th></tr></thead>
            <tbody>${rows}</tbody>
        </table>`;
    }

    function renderTechnologiesTable(technologies) {
        const flat = technologies.flatMap((entry) =>
            entry.technologies.map((t) => ({ domain: entry.domain, ...t }))
        );
        if (!flat.length) return emptyPanel("Aucune technologie détectée.");
        const rows = flat.map((t) => `
            <tr>
                <td>${escapeHtml(t.domain)}</td>
                <td>${escapeHtml(t.name)}</td>
                <td>${escapeHtml(t.version || "—")}</td>
                <td>${escapeHtml(t.category || "—")}</td>
            </tr>
        `).join("");
        return `<table class="data-table">
            <thead><tr><th>Domaine</th><th>Technologie</th><th>Version</th><th>Catégorie</th></tr></thead>
            <tbody>${rows}</tbody>
        </table>`;
    }

    function riskBadge(risk) {
        const labels = { low: "faible", medium: "moyen", high: "élevé", critical: "critique" };
        return `<span class="badge badge-risk-${escapeHtml(risk)}">${labels[risk] || risk}</span>`;
    }

    function renderTakeoverTable(candidates) {
        if (!candidates.length) return emptyPanel("Aucun candidat au subdomain takeover détecté.");

        const rows = candidates.map((c) => `
            <tr>
                <td>${escapeHtml(c.subdomain)}</td>
                <td>${escapeHtml(c.cname)}</td>
                <td>${escapeHtml(c.service)}</td>
                <td><span class="badge badge-risk-${c.confidence === "high" ? "critical" : "medium"}">${escapeHtml(c.confidence)}</span></td>
            </tr>
        `).join("");

        return `<table class="data-table">
            <thead><tr><th>Sous-domaine</th><th>CNAME</th><th>Service</th><th>Confiance</th></tr></thead>
            <tbody>${rows}</tbody>
        </table>
        <p class="empty-panel" style="font-style:normal; padding: 10px 20px;">
            Détection strictement passive — aucune tentative de revendication (bucket, app, etc.)
            n'a été effectuée. Vérification manuelle nécessaire avant tout signalement ; toute
            revendication réelle doit rester dans le cadre d'une autorisation explicite.
        </p>`;
    }

    function renderEnvironmentsTable(candidates) {
        if (!candidates.length) return emptyPanel("Aucun environnement hors-prod ou panneau d'administration détecté.");

        const rows = candidates.map((c) => `
            <tr>
                <td>${escapeHtml(c.subdomain)}</td>
                <td>${c.category === "admin_panel" ? "Panneau admin" : "Hors-prod"}</td>
                <td>${escapeHtml(c.matched_keyword)}</td>
                <td>${riskBadge(c.risk)}</td>
            </tr>
        `).join("");

        return `<table class="data-table">
            <thead><tr><th>Sous-domaine</th><th>Catégorie</th><th>Mot-clé</th><th>Risque</th></tr></thead>
            <tbody>${rows}</tbody>
        </table>
        <p class="empty-panel" style="padding: 10px 20px;">
            Détection par mot-clé sur le nom uniquement — aucune vérification de contenu.
            Le nom seul ne confirme rien, vérification manuelle nécessaire.
        </p>`;
    }

    function renderEmailSecurityPanel(emailSecurity) {
        if (!emailSecurity) return emptyPanel("Analyse SPF/DKIM/DMARC non exécutée.");

        const { spf, dmarc, dkim, email_format } = emailSecurity;

        let html = `<table class="data-table">
            <thead><tr><th>Contrôle</th><th>Statut</th><th>Détail</th></tr></thead>
            <tbody>
                <tr>
                    <td>SPF</td>
                    <td>${riskBadge(spf.risk)}</td>
                    <td>${escapeHtml(spf.detail)}</td>
                </tr>
                <tr>
                    <td>DMARC</td>
                    <td>${riskBadge(dmarc.risk)}</td>
                    <td>${escapeHtml(dmarc.detail)}</td>
                </tr>
                <tr>
                    <td>DKIM</td>
                    <td>${dkim.detected
                        ? '<span class="badge badge-clean">confirmé</span>'
                        : '<span class="badge badge-unknown">non trouvé</span>'}</td>
                    <td>${escapeHtml(dkim.detail)}</td>
                </tr>
            </tbody>
        </table>`;

        if (email_format && email_format.format) {
            html += `<p class="empty-panel" style="font-style:normal; padding: 10px 20px;">
                Format d'email dominant déduit : <strong>${escapeHtml(email_format.format)}</strong>
                (${email_format.confidence}% de confiance, ${email_format.sample_size} employé(s) analysé(s)).
            </p>`;
        }

        html += `<p class="empty-panel" style="padding: 10px 20px;">
            Note : un DKIM "non trouvé" signifie qu'aucun sélecteur courant n'a été détecté —
            pas une confirmation d'absence (sélecteur personnalisé possible).
        </p>`;

        return html;
    }

    function renderEmployeesTable(employees) {
        if (!employees.length) return emptyPanel("Aucun employé identifié.");
        const rows = employees.map((e) => `
            <tr>
                <td>${escapeHtml(e.name || "—")}</td>
                <td>${escapeHtml(e.position || "—")}</td>
                <td>${escapeHtml(e.email)}</td>
                <td>${escapeHtml(e.confidence)}</td>
            </tr>
        `).join("");
        return `<table class="data-table">
            <thead><tr><th>Nom (deviné)</th><th>Poste</th><th>Email</th><th>Confiance</th></tr></thead>
            <tbody>${rows}</tbody>
        </table>`;
    }

    function renderLeaksTable(leaks) {
        if (!leaks.length) return emptyPanel("Aucun email vérifié.");
        const rows = leaks.map((l) => {
            let badge = '<span class="badge badge-unknown">Inconnu</span>';
            if (l.leaked === true) badge = '<span class="badge badge-leaked">Compromis</span>';
            if (l.leaked === false) badge = '<span class="badge badge-clean">Aucune fuite</span>';
            const sources = (l.sources || []).map((s) => escapeHtml(s.source)).join(", ") || "—";
            return `<tr><td>${escapeHtml(l.email)}</td><td>${badge}</td><td>${sources}</td></tr>`;
        }).join("");
        return `<table class="data-table">
            <thead><tr><th>Email</th><th>Statut</th><th>Source(s)</th></tr></thead>
            <tbody>${rows}</tbody>
        </table>
        <p class="empty-panel" style="font-style:normal; padding: 10px 20px;">Aucun mot de passe n'est jamais affiché en clair.</p>`;
    }

    function emptyPanel(text) {
        return `<p class="empty-panel">${escapeHtml(text)}</p>`;
    }

    function escapeHtml(str) {
        const div = document.createElement("div");
        div.textContent = String(str);
        return div.innerHTML;
    }
})();
