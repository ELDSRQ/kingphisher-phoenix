// Presentation and field feedback only. Campaign authorization stays on the server.
export function campaignWizard({ root, el, initialStep, onStepChange, completedThrough = 0 }) {
  const labels = ["Select domain", "Sign RoE", "Recipients", "Choose/edit email", "Approve", "Send", "Monitor"];
  const panels = new Map();
  const progress = el("ol", { class: "campaign-progress" });
  const status = el("p", { class: "campaign-step-status", role: "status", "aria-live": "polite", "aria-atomic": "true" });
  const summary = el("div", { class: "campaign-errors", role: "alert", tabindex: "-1", hidden: "" });
  const container = el("div", { class: "campaign-setup" }, [
    el("nav", { "aria-label": "Campaign setup progress" }, [progress]), status, summary,
  ]);
  root.appendChild(container);
  let current;

  function show(step, focus = true) {
    if (!panels.has(step)) return;
    current = step;
    onStepChange(step);
    for (const [number, panel] of panels) panel.hidden = number !== step;
    progress.replaceChildren(...labels.map((label, index) => {
      const number = index + 1;
      const state = number === step ? "Current step" : number <= completedThrough || (panels.has(number) && number < Math.max(...panels.keys())) ? "Completed step" : panels.has(number) ? "Available step" : "Upcoming step";
      const content = [el("span", { class: "campaign-step-number", "aria-hidden": "true", text: number }),
        el("span", { text: label }), el("span", { class: "campaign-step-state", text: state })];
      return el("li", { "aria-current": number === step ? "step" : null }, [
        panels.has(number) ? el("button", { type: "button", "aria-label": `${number}. ${label}`, onclick: () => show(number) }, content)
          : el("span", { class: "campaign-step-unavailable" }, content),
      ]);
    }));
    status.textContent = `Step ${step} of ${labels.length}: ${labels[step - 1]}.`;
    // A linked error summary belongs to the step where validation occurred.
    summary.hidden = true;
    if (focus) panels.get(step).querySelector("h3").focus();
  }

  function add(step, title, children) {
    let panel = panels.get(step);
    if (!panel) {
      panel = el("section", { class: "card campaign-step", hidden: "", "aria-labelledby": `campaign-step-${step}` }, [
        el("h3", { id: `campaign-step-${step}`, tabindex: "-1", text: `${step}. ${labels[step - 1]}` }),
      ]);
      panels.set(step, panel);
      container.appendChild(panel);
    }
    panel.appendChild(el("div", { class: "campaign-step-group" }, [el("h4", { text: title }), ...children]));
    return panel;
  }

  function finish(focus = false) {
    const available = [...panels.keys()].sort((a, b) => a - b);
    for (let index = 0; index < available.length; index += 1) {
      const step = available[index];
      const actions = el("div", { class: "btn-row campaign-step-navigation" });
      if (index > 0) actions.appendChild(el("button", { type: "button", class: "btn", text: "Back", onclick: () => show(available[index - 1]) }));
      if (index < available.length - 1) actions.appendChild(el("button", { type: "button", class: "btn", text: `Continue to ${labels[available[index + 1] - 1].toLowerCase()}`, onclick: () => show(available[index + 1]) }));
      panels.get(step).appendChild(actions);
    }
    if (available.length) show(panels.has(initialStep) ? initialStep : available.at(-1), focus);
  }

  function clearField(field) {
    field.removeAttribute("aria-invalid");
    const errorId = `${field.id}-error`;
    const description = (field.getAttribute("aria-describedby") || "").split(" ").filter((id) => id && id !== errorId);
    if (description.length) field.setAttribute("aria-describedby", description.join(" "));
    else field.removeAttribute("aria-describedby");
    container.querySelector(`[id="${errorId}"]`)?.remove();
  }

  function errors(items) {
    container.querySelectorAll('[aria-invalid="true"]').forEach(clearField);
    if (!items.length) { summary.hidden = true; return true; }
    summary.replaceChildren(el("p", { text: "Check the following before continuing:" }), el("ul", {}, items.map(({ field, message }) => {
      field.setAttribute("aria-invalid", "true");
      const errorId = `${field.id}-error`;
      const descriptions = (field.getAttribute("aria-describedby") || "").split(" ").filter(Boolean);
      field.setAttribute("aria-describedby", [...descriptions, errorId].join(" "));
      field.insertAdjacentElement("afterend", el("p", { id: errorId, class: "campaign-field-error", text: message }));
      const focusField = () => {
        const panel = [...panels].find(([, node]) => node.contains(field));
        if (panel && panel[0] !== current) show(panel[0], false);
        for (let node = field.parentElement; node && node !== container; node = node.parentElement) {
          if (node.tagName === "DETAILS") node.open = true;
        }
        field.focus();
      };
      return el("li", {}, [el("a", { href: `#${field.id}`, text: message, onclick: (event) => { event.preventDefault(); focusField(); } })]);
    })));
    summary.hidden = false;
    summary.focus();
    return false;
  }

  function validate(form) {
    const items = [...form.querySelectorAll("input, select, textarea")].filter((field) => !field.checkValidity()).map((field) => {
      const label = field.labels?.[0]?.textContent || "This field";
      const message = field.validity.valueMissing ? `${label}: enter a value.`
        : field.validity.typeMismatch ? `${label}: enter a valid email address.` : `${label}: ${field.validationMessage}`;
      return { field, message };
    });
    return errors(items);
  }

  container.addEventListener("input", (event) => {
    if (event.target.getAttribute("aria-invalid") === "true") clearField(event.target);
    // Clear resolved summaries on edit; the next attempt validates all fields.
    summary.hidden = true;
  });
  return { add, finish, validate, errors };
}
