// Administrator hold controls. No hold is created until its explicit form action.
export async function renderRetentionHolds(root, { el, api, hasCapability, CAPABILITY, promptDialog, confirmDialog, toast }) {
  const panel = el("section", { class: "card", "aria-labelledby": "retention-holds-title" }, [
    el("h3", { id: "retention-holds-title", text: "Retention holds" }),
    el("p", { text: "A hold pauses irreversible deletion across this tenant, including retention expiry, recipient erasure and keyed awareness-ledger purges. It does not stop campaign delivery, revoke links or extend a privacy-request deadline." }),
  ]);
  root.appendChild(panel);
  const content = el("div"); panel.appendChild(content);
  const error = el("p", { role: "alert", class: "modal-error", tabindex: "-1" }); panel.appendChild(error);
  const administrator = hasCapability(CAPABILITY.MANAGE_ROLES);
  let pendingHold = null;
  async function refresh() {
    error.textContent = "";
    try {
      const status = await api("/privacy/retention-holds/status");
      const records = administrator ? await api("/privacy/retention-holds?limit=100&offset=0") : { items: [] };
      content.replaceChildren(el("p", { role: "status", text: status.active
        ? "Deletion paused: an active retention hold preserves tenant data. Erasure requests remain open."
        : "No active retention hold. Normal retention and verified erasure apply." }));
      if (!administrator) { content.appendChild(el("p", { text: "An administrator manages holds and their release." })); return; }
      content.appendChild(el("button", { class: "btn", type: "button", text: "Set a retention hold", onclick: async () => {
        const values = await promptDialog({ title: "Set a retention hold", description:
          "Pause all tenant retention and erasure purges until this hold is explicitly released. Use a case reference and avoid employee personal data. Holds do not expire automatically.",
          fields: [{ name: "reference", label: "Case reference", required: true, maxLength: 255 },
            { name: "reason", label: "Preservation reason", type: "textarea", required: true, maxLength: 2000 }], submitLabel: "Set hold" });
        if (!values) return;
        if (!pendingHold || pendingHold.reference !== values.reference || pendingHold.reason !== values.reason) {
          pendingHold = { hold_id: crypto.randomUUID(), reference: values.reference, reason: values.reason };
        }
        try { await api("/privacy/retention-holds", { method: "POST", body: JSON.stringify(pendingHold) }); pendingHold = null; await refresh(); toast("Retention hold set. Deletion is paused.", "success"); }
        catch (e) { error.textContent = e.message; error.focus(); }
      } }));
      if ((records.items || []).length === 100) content.appendChild(el("p", { text: "Showing the first 100 holds, with active holds first. The protected API provides paginated history." }));
      for (const hold of records.items || []) {
        const row = el("div", { class: "context-help" }, [
          el("h4", { text: `${hold.reference} — ${hold.active ? "Active" : "Released"}` }),
          el("p", { text: hold.reason }),
          el("p", { text: `Set by ${hold.created_by} on ${new Date(hold.created_at).toLocaleString()}.` }),
        ]);
        if (hold.active) row.appendChild(el("button", { class: "btn", type: "button", text: `Release hold: ${hold.reference}`, onclick: async (event) => {
          const button = event.currentTarget;
          const values = await promptDialog({ title: "Release this retention hold?", description:
            "Other active holds will continue to block deletion. Once all holds are released, eligible records may be deleted by the next normal retention run or an explicit erasure request.",
            fields: [{ name: "reason", label: "Release reason", type: "textarea", required: true, maxLength: 2000 }], submitLabel: "Review release" });
          if (!values || !await confirmDialog({ title: "Confirm hold release", message: `Release ${hold.reference}?`, detail: { "Release reason": values.reason }, confirmLabel: "Release hold" })) return;
          button.disabled = true;
          try { await api(`/privacy/retention-holds/${hold.hold_id}/release`, { method: "POST", body: JSON.stringify({ reason: values.reason }) }); await refresh(); toast("Hold release recorded.", "success"); }
          catch (e) { error.textContent = e.message; error.focus(); } finally { if (button.isConnected) button.disabled = false; }
        } }));
        else row.appendChild(el("p", { text: `Released by ${hold.released_by} on ${new Date(hold.released_at).toLocaleString()}: ${hold.release_reason}` }));
        content.appendChild(row);
      }
    } catch {
      content.replaceChildren(el("p", { role: "status", text: "Hold status is unavailable. Erasure remains blocked until preservation state can be verified." }),
        el("button", { class: "btn", type: "button", text: "Retry hold status", onclick: refresh }));
    }
  }
  await refresh();
}
