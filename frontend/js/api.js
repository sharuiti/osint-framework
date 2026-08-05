/**
 * api.js
 * Couche d'accès à l'API FastAPI (étape 5). Aucune logique d'affichage
 * ici — juste des appels réseau et le polling de statut.
 *
 * Pour pointer vers un backend distant, change API_BASE.
 */
const API_BASE = "http://127.0.0.1:8000";

class ApiError extends Error {
    constructor(status, message) {
        super(message);
        this.status = status;
    }
}

async function apiCheckHealth() {
    // /health renvoie l'état du serveur + les outils externes détectés.
    // Une erreur réseau (serveur injoignable) signifie "API down".
    try {
        const res = await fetch(`${API_BASE}/health`);
        if (!res.ok) return { up: false };
        const data = await res.json();
        return { up: true, ...data };
    } catch {
        return { up: false };
    }
}

async function apiListScans({ limit = 20, offset = 0, domain = null } = {}) {
    const params = new URLSearchParams({ limit, offset });
    if (domain) params.set("domain", domain);

    const res = await fetch(`${API_BASE}/scans?${params}`);
    if (!res.ok) {
        throw new ApiError(res.status, "Impossible de charger l'historique.");
    }
    return res.json();
}

async function apiDeleteScan(scanId) {
    const res = await fetch(`${API_BASE}/scan/${scanId}`, { method: "DELETE" });
    if (!res.ok && res.status !== 204) {
        throw new ApiError(res.status, "Suppression impossible.");
    }
    return true;
}

async function apiStartScan(domain, provider, techEngine) {
    const res = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, provider, tech_engine: techEngine }),
    });

    if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const detail = Array.isArray(body.detail)
            ? body.detail.map((d) => d.msg).join(" — ")
            : body.detail || "Requête invalide.";
        throw new ApiError(res.status, detail);
    }

    return res.json();
}

async function apiGetStatus(scanId) {
    const res = await fetch(`${API_BASE}/scan/${scanId}/status`);
    if (!res.ok) {
        throw new ApiError(res.status, "Impossible de récupérer le statut du scan.");
    }
    return res.json();
}

async function apiGetResults(scanId) {
    const res = await fetch(`${API_BASE}/scan/${scanId}/results`);
    if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new ApiError(res.status, body.detail || "Résultats indisponibles.");
    }
    return res.json();
}

function apiGetReportUrl(scanId) {
    return `${API_BASE}/scan/${scanId}/report`;
}

/**
 * Interroge /status toutes les `intervalMs` jusqu'à ce que le scan
 * soit "done" ou "failed". Appelle onUpdate à chaque tick, même sans
 * changement, pour permettre un rendu réactif côté UI.
 */
async function pollScanStatus(scanId, { onUpdate, intervalMs = 2000, timeoutMs = 10 * 60 * 1000 } = {}) {
    const startedAt = Date.now();

    while (true) {
        const status = await apiGetStatus(scanId);
        onUpdate(status);

        if (status.status === "done" || status.status === "failed") {
            return status;
        }

        if (Date.now() - startedAt > timeoutMs) {
            throw new ApiError(0, "Le scan prend anormalement longtemps (timeout côté interface).");
        }

        await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
}
