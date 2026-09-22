import fixture from "../banks/us/mercury/fixtures/sent.synthetic.json";
import { interpretMercury } from "../banks/us/mercury/transformer.js";

const prompt = document.querySelector<HTMLElement>("#agent-prompt");
const copyStatus = document.querySelector<HTMLElement>("#copy-status");
document.querySelector("#copy-prompt")?.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(prompt?.textContent ?? "");
    if (copyStatus) copyStatus.textContent = "Copied. Paste into your coding agent.";
  } catch {
    if (copyStatus) copyStatus.textContent = "Select the prompt above and copy it manually.";
  }
});
for (const button of document.querySelectorAll<HTMLButtonElement>("[data-scenario]")) {
  button.addEventListener("click", () => {
    for (const b of document.querySelectorAll("[data-scenario]")) {
      b.classList.remove("selected");
      b.setAttribute("aria-pressed", "false");
    }
    button.classList.add("selected");
    button.setAttribute("aria-pressed", "true");
    const input = structuredClone(fixture.input);
    if (button.dataset.scenario === "pending") input.data.transactions[0].status = "pending";
    if (button.dataset.scenario === "missing")
      input.data.transactions[0].details.domesticWireRoutingInfo.accountNumber = "••0001";
    const result = interpretMercury(input, fixture.transactionId);
    const status = document.querySelector("#example-status");
    if (status) status.textContent = input.data.transactions[0].status;
    const resultNode = document.querySelector("#example-result");
    const note = document.querySelector("#example-note");
    if (resultNode) {
      resultNode.textContent =
        result.outcome === "supported" ? "Supported interpretation" : "Insufficient evidence";
      resultNode.classList.toggle("warning", result.outcome !== "supported");
    }
    if (note)
      note.textContent =
        result.outcome === "supported"
          ? "Sender-bank evidence. Recipient credit and source authenticity remain unproven."
          : result.reason;
  });
}
type Provider = {
  name: string;
  id: string;
  country: string;
  currencies: string[];
  capability: string;
  source: string;
  reportCount: number;
};
const list = document.querySelector("#provider-list");
const search = document.querySelector<HTMLInputElement>("#provider-search");
function render(providers: Provider[]) {
  if (!list) return;
  list.replaceChildren();
  if (!providers.length) {
    const p = document.createElement("p");
    p.className = "empty";
    p.textContent = "No integration found. Yours could be next—open a bank request below.";
    list.append(p);
    return;
  }
  for (const p of providers) {
    const card = document.createElement("article");
    card.className = "provider-card";
    const identity = document.createElement("div");
    identity.className = "provider-identity";
    const logo = document.createElement("span");
    logo.className = "provider-logo";
    logo.textContent = p.name.slice(0, 1);
    const text = document.createElement("div");
    const title = document.createElement("h3");
    title.textContent = p.name;
    const country = document.createElement("p");
    country.textContent = `${p.country} · ${p.currencies.join(", ")}`;
    text.append(title, country);
    identity.append(logo, text);
    const badge = document.createElement("span");
    badge.className = "badge";
    badge.textContent = "Experimental";
    const description = document.createElement("p");
    description.textContent = p.capability;
    const link = document.createElement("a");
    link.className = "text-link";
    link.href = p.source;
    link.textContent = "View integration ↗";
    card.append(identity, badge, description, link);
    const count = document.createElement("p");
    count.className = "report-count";
    count.textContent = `${p.reportCount} revision-specific community report${p.reportCount === 1 ? "" : "s"} · View scope and limitations in the repository.`;
    count.style.gridColumn = "1 / -1";
    card.append(count);
    list.append(card);
  }
}
fetch("/catalog.json")
  .then((r) => {
    if (!r.ok) throw new Error("Catalog unavailable");
    return r.json();
  })
  .then((data: { providers: Provider[] }) => {
    render(data.providers);
    search?.addEventListener("input", () => {
      const q = search.value.toLowerCase().trim();
      render(
        data.providers.filter((p) =>
          `${p.name} ${p.country} ${p.capability}`.toLowerCase().includes(q),
        ),
      );
    });
  })
  .catch(() => {
    if (search) {
      search.disabled = true;
      search.placeholder = "Catalog unavailable";
    }
  });
