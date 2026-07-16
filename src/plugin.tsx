import { useEffect, useMemo, useState, type ComponentType } from "react";
import styles from "./web/styles.css?inline";

type AppContext = {
  api: { request<T>(path: string, init?: RequestInit): Promise<T> };
  privileges: string[];
  localization?: { locale: string };
};
type Row = Record<string, unknown>;
type View =
  | "dashboard"
  | "products"
  | "customers"
  | "instances"
  | "grants"
  | "activations"
  | "licenses"
  | "security"
  | "audit";

const messages = {
  en: {
    dashboard: "Dashboard",
    products: "Products",
    customers: "Customers",
    instances: "Core instances",
    grants: "License grants",
    activations: "Activations",
    licenses: "Issued licenses",
    security: "Security",
    audit: "Audit",
    refresh: "Refresh",
    create: "Create",
    approve: "Approve",
    reject: "Reject",
    issue: "Issue",
    renew: "Renew",
    revoke: "Revoke",
    suspend: "Suspend",
    activate: "Activate",
    pending: "Pending",
    activeLicenses: "Active licenses",
    expiring: "Expiring",
    failed: "Failed activations",
    activeCustomers: "Active customers",
    noRecords: "No records.",
    name: "Name",
    appId: "Application ID",
    company: "Company",
    edition: "Edition",
    status: "Status",
    actions: "Actions",
    offlineImport: "Import offline request",
    jsonRequest: "Signed request JSON",
    certificate: "Author certificate JWS",
    signingKey: "Signing key",
    certificateExpiry: "Certificate expiry",
    save: "Save",
    close: "Close",
  },
  cs: {
    dashboard: "Přehled",
    products: "Produkty",
    customers: "Zákazníci",
    instances: "Instance Core",
    grants: "Licenční granty",
    activations: "Aktivace",
    licenses: "Vydané licence",
    security: "Zabezpečení",
    audit: "Audit",
    refresh: "Obnovit",
    create: "Vytvořit",
    approve: "Schválit",
    reject: "Zamítnout",
    issue: "Vydat",
    renew: "Obnovit",
    revoke: "Odvolat",
    suspend: "Pozastavit",
    activate: "Aktivovat",
    pending: "Čekající",
    activeLicenses: "Aktivní licence",
    expiring: "Brzy končící",
    failed: "Neúspěšné aktivace",
    activeCustomers: "Aktivní zákazníci",
    noRecords: "Žádné záznamy.",
    name: "Název",
    appId: "ID aplikace",
    company: "Společnost",
    edition: "Edice",
    status: "Stav",
    actions: "Akce",
    offlineImport: "Importovat offline žádost",
    jsonRequest: "Podepsaná žádost JSON",
    certificate: "JWS certifikátu autora",
    signingKey: "Podpisový klíč",
    certificateExpiry: "Konec platnosti certifikátu",
    save: "Uložit",
    close: "Zavřít",
  },
};

function ensureStyles() {
  if (document.getElementById("hc-licensing-styles")) return;
  const el = document.createElement("style");
  el.id = "hc-licensing-styles";
  el.textContent = styles;
  document.head.appendChild(el);
}

function createPage(
  view: View,
  context: AppContext,
): ComponentType<Record<string, never>> {
  return function LicensingView() {
    const lang = context.localization?.locale === "cs" ? "cs" : "en";
    const t = messages[lang];
    const [data, setData] = useState<Row[]>([]);
    const [summary, setSummary] = useState<Row>({});
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState("");
    const [form, setForm] = useState(false);
    const load = async () => {
      setBusy(true);
      setError("");
      try {
        if (view === "dashboard" || view === "security")
          setSummary(await context.api.request<Row>("/v1/admin/dashboard"));
        else
          setData(
            (await context.api.request<{ items: Row[] }>(`/v1/admin/${view}`))
              .items,
          );
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setBusy(false);
      }
    };
    useEffect(() => {
      void load();
    }, [view]);
    const act = async (path: string, body?: unknown) => {
      setBusy(true);
      try {
        await context.api.request(path, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body ?? {}),
        });
        await load();
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
        setBusy(false);
      }
    };
    const fields = useMemo(
      () =>
        view === "products"
          ? ["app_id", "name", "description"]
          : view === "customers"
            ? ["company_name", "notes"]
            : view === "instances"
              ? ["customer_id", "platform_instance_id", "callback_url"]
              : view === "grants"
                ? ["customer_id", "product_id", "edition"]
                : [],
      [view],
    );
    const submit = async (e: React.FormEvent<HTMLFormElement>) => {
      e.preventDefault();
      const values = Object.fromEntries(new FormData(e.currentTarget));
      if (view === "grants")
        Object.assign(values, { status: "active", offline_allowed: true });
      await act(`/v1/admin/${view}`, values);
      setForm(false);
    };
    if (view === "dashboard")
      return (
        <main className="lic">
          <header>
            <div>
              <h1>{t.dashboard}</h1>
              <p>License issuing and activation operations</p>
            </div>
            <button onClick={load}>{t.refresh}</button>
          </header>
          {error && <div className="err">{error}</div>}
          <section className="stats">
            {[
              [t.activeLicenses, "active_licenses"],
              [t.expiring, "expiring_licenses"],
              [t.failed, "failed_activations"],
              [t.pending, "pending_activations"],
              [t.activeCustomers, "active_customers"],
            ].map(([label, key]) => (
              <div>
                <strong>{String(summary[key] ?? 0)}</strong>
                <span>{label}</span>
              </div>
            ))}
          </section>
        </main>
      );
    if (view === "security")
      return (
        <main className="lic">
          <header>
            <div>
              <h1>{t.security}</h1>
              <p>
                {t.signingKey}: {String(summary["signing_key_kid"] ?? "-")} ·{" "}
                {t.certificateExpiry}:{" "}
                {String(summary["certificate_expires_at"] ?? "-")}
              </p>
            </div>
          </header>
          {error && <div className="err">{error}</div>}
          <form
            className="editor"
            onSubmit={async (e) => {
              e.preventDefault();
              await act("/v1/admin/security/certificate", {
                author_cert_jws: String(
                  new FormData(e.currentTarget).get("certificate"),
                ),
              });
            }}
          >
            <label>
              {t.certificate}
              <textarea name="certificate" required rows={8} />
            </label>
            <div>
              <button className="primary" type="submit">
                {t.save}
              </button>
            </div>
          </form>
        </main>
      );
    return (
      <main className="lic">
        <header>
          <div>
            <h1>{t[view]}</h1>
            <p>{data.length} records</p>
          </div>
          <div>
            {view === "activations" && (
              <button onClick={() => setForm(true)}>{t.offlineImport}</button>
            )}
            {fields.length > 0 && (
              <button className="primary" onClick={() => setForm(true)}>
                {t.create}
              </button>
            )}
            <button onClick={load}>{t.refresh}</button>
          </div>
        </header>
        {error && <div className="err">{error}</div>}
        {form && (
          <form
            className="editor"
            onSubmit={async (e) => {
              if (view === "activations") {
                e.preventDefault();
                try {
                  await act(
                    "/v1/admin/activations/offline",
                    JSON.parse(
                      String(new FormData(e.currentTarget).get("request")),
                    ),
                  );
                  setForm(false);
                } catch {}
              } else await submit(e);
            }}
          >
            {view === "activations" ? (
              <label>
                {t.jsonRequest}
                <textarea name="request" required rows={7} />
              </label>
            ) : (
              fields.map((field) => (
                <label>
                  {field.replaceAll("_", " ")}
                  <input
                    name={field}
                    required={
                      !field.includes("description") &&
                      !field.includes("notes") &&
                      !field.includes("callback")
                    }
                  />
                </label>
              ))
            )}
            <div>
              <button className="primary" type="submit">
                {t.save}
              </button>
              <button type="button" onClick={() => setForm(false)}>
                {t.close}
              </button>
            </div>
          </form>
        )}
        <div className="table">
          <div className="tr head">
            <span>{t.name}</span>
            <span>{t.status}</span>
            <span>{t.actions}</span>
          </div>
          {data.length === 0 && !busy && <p>{t.noRecords}</p>}
          {data.map((row) => {
            const rid = String(
              row[`${view.slice(0, -1)}_id`] ??
                row["activation_id"] ??
                row["license_id"] ??
                row["id"] ??
                "",
            );
            const title = String(
              row["name"] ??
                row["company_name"] ??
                row["product_name"] ??
                row["serial_number"] ??
                row["operation"] ??
                row["app_id"] ??
                rid,
            );
            return (
              <div className="tr" key={rid + title}>
                <span>
                  <strong>{title}</strong>
                  <small>
                    {String(
                      row["app_id"] ??
                        row["customer_name"] ??
                        row["tenant_id"] ??
                        row["username"] ??
                        "",
                    )}
                  </small>
                </span>
                <span>{String(row["status"] ?? row["outcome"] ?? "")}</span>
                <span className="actions">
                  {view === "activations" && row["status"] === "pending" && (
                    <>
                      <button
                        onClick={() =>
                          act(`/v1/admin/activations/${rid}/decision`, {
                            approved: true,
                          })
                        }
                      >
                        {t.approve}
                      </button>
                      <button
                        onClick={() =>
                          act(`/v1/admin/activations/${rid}/decision`, {
                            approved: false,
                          })
                        }
                      >
                        {t.reject}
                      </button>
                    </>
                  )}
                  {view === "activations" && row["status"] === "approved" && (
                    <button
                      onClick={() => act(`/v1/admin/activations/${rid}/issue`)}
                    >
                      {t.issue}
                    </button>
                  )}
                  {view === "licenses" && row["status"] === "active" && (
                    <>
                      <button onClick={() => act(`/v1/admin/licenses/${rid}/renew`)}>{t.renew}</button>
                      <button onClick={() => act(`/v1/admin/licenses/${rid}/status`, { status: "revoked", reason: "Revoked by operator" })}>{t.revoke}</button>
                    </>
                  )}
                  {view === "grants" && (
                    <button onClick={() => act(`/v1/admin/grants/${rid}/status`, { status: row["status"] === "active" ? "suspended" : "active" })}>
                      {row["status"] === "active" ? t.suspend : t.activate}
                    </button>
                  )}
                  {view === "instances" && !row["revoked_at"] && (
                    <button onClick={() => act(`/v1/admin/instances/${rid}/revoke`)}>{t.revoke}</button>
                  )}
                </span>
              </div>
            );
          })}
        </div>
      </main>
    );
  };
}

export function register(context: AppContext) {
  ensureStyles();
  const locale = context.localization?.locale === "cs" ? "cs" : "en";
  const t = messages[locale];
  const views: View[] = [
    "dashboard",
    "products",
    "customers",
    "instances",
    "grants",
    "activations",
    "licenses",
    "security",
    "audit",
  ];
  return {
    routes: views.map((view) => ({
      path: view === "dashboard" ? "" : view,
      component: createPage(view, context),
    })),
    nav_entries: views.map((view) => ({
      label: t[view],
      path: `/app/licensing${view === "dashboard" ? "" : `/${view}`}`,
    })),
    dashboard_widgets: [],
  };
}
