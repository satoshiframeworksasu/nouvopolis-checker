/**
 * The standalone check page (check.html; docs/plans/snapshots.md 8.2): the
 * user chooses the export's zip file, and optionally the provider's root
 * certificate; the page runs check.ts and lists what matched. Built into one
 * self-contained HTML file by scripts/build-checker.mjs. Its Content Security
 * Policy allows no connection: it cannot send anything anywhere.
 *
 * Every sentence comes from the export's locale (the JSON block "texts"); the
 * page holds none of its own (D3).
 */
import { checkArchive, type Line } from "./check";
import type { CheckerTexts } from "./texts";
import { readZip } from "./zip-read";

const texts = JSON.parse(document.getElementById("texts")?.textContent ?? "{}") as CheckerTexts;
const licences = JSON.parse(document.getElementById("licences")?.textContent ?? "[]") as { name: string; license: string; text: string }[];
const say = (key: keyof CheckerTexts, params: Record<string, string> = {}) => (texts[key] ?? key).replace(/\{(\w+)\}/g, (m, k: string) => params[k] ?? m);

function el<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, string> = {}, ...children: (Node | string)[]): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  node.append(...children);
  return node;
}

const readFile = (file: File) => file.arrayBuffer().then((b) => new Uint8Array(b));

function render(root: HTMLElement) {
  document.title = say("evidenceCheck.page.title");
  const zipInput = el("input", { type: "file", id: "zip", accept: ".zip,application/zip" });
  const rootInput = el("input", { type: "file", id: "root", accept: ".pem,.crt,.cer" });
  const button = el("button", { type: "submit", id: "run" }, say("evidenceCheck.page.run"));
  const results = el("ol", { id: "results" });
  const summary = el("p", { id: "summary", role: "status" });
  const form = el(
    "form",
    {},
    el("p", {}, el("label", { for: "zip" }, say("evidenceCheck.page.choose")), el("br"), zipInput),
    el("p", {}, el("label", { for: "root" }, say("evidenceCheck.page.root")), el("br"), rootInput, el("br"), el("small", {}, say("evidenceCheck.page.rootHelp"))),
    el("p", {}, button),
  );
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void run();
  });

  async function run() {
    const zipFile = zipInput.files?.[0];
    if (!zipFile) return;
    button.disabled = true;
    button.textContent = say("evidenceCheck.page.working");
    results.replaceChildren();
    summary.textContent = "";
    summary.removeAttribute("data-result");
    try {
      let files: Map<string, Uint8Array>;
      try {
        files = readZip(await readFile(zipFile));
      } catch {
        summary.textContent = say("evidenceCheck.page.notZip");
        summary.setAttribute("data-result", "fail");
        return;
      }
      const rootFile = rootInput.files?.[0];
      const anchorPem = rootFile ? new TextDecoder().decode(await readFile(rootFile)) : undefined;
      const lines: Line[] = await checkArchive(files, { anchorPem });
      for (const line of lines) {
        const label = say(line.status === "ok" ? "evidenceCheck.page.ok" : line.status === "fail" ? "evidenceCheck.page.fail" : "evidenceCheck.page.note");
        results.append(el("li", { "data-status": line.status, "data-key": line.key }, el("strong", {}, label), " ", say(line.key, line.params ?? {}), " ", el("code", {}, line.subject)));
      }
      const failed = lines.some((l) => l.status === "fail");
      summary.textContent = say(failed ? "evidenceCheck.msg.summaryBad" : "evidenceCheck.msg.summaryOk");
      summary.setAttribute("data-result", failed ? "fail" : "ok");
    } finally {
      button.disabled = false;
      button.textContent = say("evidenceCheck.page.run");
    }
  }

  const licenceList = el("details", {}, el("summary", {}, say("evidenceCheck.page.licences")), ...licences.map((l) => el("section", {}, el("h3", {}, `${l.name} (${l.license})`), el("pre", {}, l.text))));
  root.replaceChildren(
    el("h1", {}, say("evidenceCheck.page.title")),
    // Its own version, and where to compare its SHA-256 (the published copies, nouvopolis.com/check).
    el("p", { id: "version" }, say("evidenceCheck.msg.version"), " ", say("evidenceCheck.msg.compare")),
    el("p", {}, say("evidenceCheck.page.lead")),
    el("p", {}, say("evidenceExport.readme.seal")),
    form,
    summary,
    results,
    licenceList,
  );
}

render(document.getElementById("app")!);
