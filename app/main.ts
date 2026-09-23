import fixture from "../banks/us/mercury/fixtures/sent.synthetic.json";
import { interpretMercury } from "../banks/us/mercury/transformer.js";
import bounties from "./bounties.json";

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
const count = document.querySelector<HTMLElement>("#provider-count");
const countryNames = new Intl.DisplayNames(["en"], { type: "region" });

type Integration = {
  name: string;
  country: string;
  currency: string;
  href: string;
  logo: string | null;
  mark: string;
  amount?: number;
};

function render(providers: Provider[], query = "") {
  if (!list) return;
  list.replaceChildren();
  const integrations: Integration[] = [
    ...providers.map((provider) => ({
      name: provider.name,
      country: provider.country,
      currency: provider.currencies.join(", "),
      href: provider.source,
      logo: provider.id === "us/mercury" ? "/logos/mercury.svg" : null,
      mark: provider.name.slice(0, 2).toUpperCase(),
    })),
    ...bounties.map((bounty) => ({
      name: bounty.name,
      country: bounty.country,
      currency: bounty.currency,
      href: bounty.issue,
      logo: bounty.logo,
      mark: bounty.mark,
      amount: bounty.amount,
    })),
  ].filter((integration) => {
    const place = countryNames.of(integration.country) ?? integration.country;
    return `${integration.name} ${place} ${integration.currency}`
      .toLowerCase()
      .includes(query.toLowerCase().trim());
  });

  if (count)
    count.textContent = query
      ? `${integrations.length} matching integration${integrations.length === 1 ? "" : "s"}`
      : `${providers.length} in repo · ${bounties.length} bounty targets`;

  if (!integrations.length) {
    const p = document.createElement("p");
    p.className = "empty";
    p.textContent = "No match yet. Propose your bank below.";
    list.append(p);
    return;
  }
  for (const integration of integrations) {
    const available = integration.amount === undefined;
    const card = document.createElement("a");
    card.className = `integration-tile ${available ? "is-available" : "is-bounty"}`;
    card.href = integration.href;
    const place = countryNames.of(integration.country) ?? integration.country;
    card.setAttribute(
      "aria-label",
      available
        ? `${integration.name}, ${place}, experimental integration in the repository. View scope and limitations.`
        : `${integration.name}, ${place}, $${integration.amount} bounty target. View issue for terms.`,
    );
    const logo = document.createElement("span");
    logo.className = "integration-logo";
    if (integration.logo) {
      const img = document.createElement("img");
      img.src = integration.logo;
      img.alt = "";
      img.loading = "lazy";
      img.addEventListener("error", () => {
        img.remove();
        logo.textContent = integration.mark;
      });
      logo.append(img);
    } else {
      logo.textContent = integration.mark;
    }
    const name = document.createElement("strong");
    name.className = "integration-name";
    name.textContent = integration.name;
    const meta = document.createElement("span");
    meta.className = "integration-meta";
    meta.textContent = `${place} · ${integration.currency}`;
    const status = document.createElement("span");
    status.className = "integration-status";
    status.textContent = available ? "In repo" : `$${integration.amount}`;
    const tooltip = document.createElement("span");
    tooltip.className = "integration-tooltip";
    tooltip.setAttribute("aria-hidden", "true");
    tooltip.textContent = available
      ? "View experimental scope ↗"
      : `Integrate this bank · $${integration.amount} bounty ↗`;
    card.append(logo, name, meta, status, tooltip);
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
      render(data.providers, search.value);
    });
  })
  .catch(() => {
    render([]);
    search?.addEventListener("input", () => render([], search.value));
  });
