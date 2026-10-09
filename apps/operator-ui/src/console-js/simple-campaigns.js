/* The primary operator journey. Technical review snapshots remain server work. */
export function installSimpleCampaigns(ui) {
  const { views, api, el, boundedCollection, hasCapability, CAPABILITY, sessionInfo,
    toast, navigateTo, dialogShell, openDialog, confirmDialog, promptDialog,
    guardUnsavedForm, markFormSaved, showCampaignReport } = ui;
  const key = "kp_campaign_setup";
  let flow;
  try { flow = JSON.parse(sessionStorage.getItem(key) || "{}"); } catch { flow = {}; }
  // Store identifiers only. Uploaded personal data and edited wording stay in memory.
  const save = () => sessionStorage.setItem(key, JSON.stringify(flow));
  window.addEventListener("kp-select-library-template", (event) => {
    flow.sourceTemplateId = event.detail.templateId; delete flow.templateId; emailContent = null; save();
  });
  let csvText = "", importPreview = null, emailContent = null;
  const activeRoe = (r) => !r.revoked_at && Date.parse(r.window_start) <= Date.now()
    && Date.parse(r.window_end) > Date.now();
  const button = (text, onclick, disabled = false, primary = false) => el("button", {
    type: "button", class: `btn${primary ? " primary" : ""}`, text, onclick,
    disabled: disabled ? "disabled" : null,
  });
  const table = (headers, rows, label) => el("div", { class: "table-scroll" }, [el("table", {
    "aria-label": label,
  }, [el("thead", {}, [el("tr", {}, headers.map((text) => el("th", { scope: "col", text })))]),
    el("tbody", {}, rows.map((row) => el("tr", {}, row.map((value) => el("td", { text: String(value ?? "—") }))))),
  ])]);
  const card = (title, children) => el("section", { class: "card" }, [el("h3", { text: title }), ...children]);
  const field = (form, label, id, attrs = {}) => {
    const input = el(attrs.rows ? "textarea" : "input", { id, ...attrs });
    form.append(el("label", { for: id, text: label }), input);
    return input;
  };
  const fail = (node, error) => { node.textContent = error.message; toast(error.message, "error"); };

  function downloadTemplate() {
    const url = URL.createObjectURL(new Blob(["\uFEFFemail,name,department\r\n"], { type: "text/csv;charset=utf-8" }));
    const link = el("a", { href: url, download: "recipient-roster-template.csv" });
    document.body.appendChild(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function monitor(campaign, target) {
    target.replaceChildren(el("p", { role: "status", text: "Loading recipient results…" }));
    try {
      const items = await boundedCollection(`/campaigns/${campaign.campaign_id}/recipients`, "items");
      target.replaceChildren(el("h3", { text: `Recipient results: ${campaign.title}` }),
        el("p", { text: "Clicks are observed link requests; automated email scanners can generate them. Confirmed interaction indicates a human action on the training page." }),
        el("p", { class: "notice", text: "Replies: unavailable. This deployment has no recipient-reply ingestion. Employee-reported phishing is a separate metric." }),
        table(["Recipient", "Delivery", "Clicked", "Confirmed interaction", "Reported", "Training"], items.map((r) => [
          `${r.display_name || "Unnamed"} (${r.masked_mailbox || "masked"})`, r.send_state,
          r.clicked ? "Yes" : "No", r.confirmed_interaction ? "Yes" : "No", r.reported ? "Yes" : "No", r.training_state,
        ]), "Campaign recipient results"),
        button("Refresh recipient results", () => monitor(campaign, target)));
    } catch (e) { target.replaceChildren(el("p", { role: "alert", text: e.message })); }
  }

  const oldDashboard = views.dashboard;
  views.dashboard = async (root) => {
    await oldDashboard(root);
    if (!hasCapability(CAPABILITY.VIEW_NAMED_RESULTS) || !root.isConnected) return;
    const panel = card("Monitor recipients", []);
    root.appendChild(panel);
    try {
      const campaigns = await boundedCollection("/campaigns");
      const choice = el("select", { id: "monitor-campaign" }, [
        el("option", { value: "", text: "Choose a campaign…" }),
        ...campaigns.map((c) => el("option", { value: c.campaign_id, text: c.title })),
      ]);
      const results = el("div");
      panel.append(el("label", { for: "monitor-campaign", text: "Campaign" }), choice, results);
      choice.addEventListener("change", () => {
        const campaign = campaigns.find((c) => c.campaign_id === choice.value);
        if (campaign) { flow.monitorId = campaign.campaign_id; save(); monitor(campaign, results); }
        else results.replaceChildren();
      });
      if (campaigns.some((c) => c.campaign_id === flow.monitorId)) {
        choice.value = flow.monitorId;
        await monitor(campaigns.find((c) => c.campaign_id === flow.monitorId), results);
      }
    } catch (e) { panel.appendChild(el("p", { role: "alert", text: e.message })); }
  };

  views.campaigns = async (root) => {
    if (!hasCapability(CAPABILITY.VIEW_AGGREGATE)) return;
    root.append(el("h2", { text: "Campaigns" }), el("p", { class: "sub", text:
      "Select domain → sign RoE → upload and confirm recipients → choose and edit an email → approve → send → monitor." }));
    const error = el("p", { role: "alert", class: "modal-error" }); root.appendChild(error);
    let campaigns, domains, roes, templates, patterns, lessons, onboarding;
    try {
      [campaigns, domains, roes, templates, patterns, lessons, onboarding] = await Promise.all([
        boundedCollection("/campaigns"),
        hasCapability(CAPABILITY.VERIFY_DOMAIN) ? boundedCollection("/sending-domains", "domains") : Promise.resolve([]),
        hasCapability(CAPABILITY.SIGN_ROE) ? boundedCollection("/roe", "roes") : Promise.resolve([]),
        hasCapability(CAPABILITY.CREATE_CAMPAIGN) ? boundedCollection("/templates") : Promise.resolve([]),
        hasCapability(CAPABILITY.CREATE_CAMPAIGN) ? boundedCollection("/patterns") : Promise.resolve([]),
        hasCapability(CAPABILITY.CREATE_CAMPAIGN) ? boundedCollection("/training-resources?approval_state=approved") : Promise.resolve([]),
        hasCapability(CAPABILITY.MANAGE_ROLES) ? api("/console/onboarding") : Promise.resolve(null),
      ]);
    } catch (e) { fail(error, e); root.appendChild(button("Retry", () => { root.replaceChildren(); views.campaigns(root); })); return; }
    if (!root.isConnected) return;
    const redraw = async () => { root.replaceChildren(); await views.campaigns(root); };
    const own = campaigns.find((c) => c.campaign_id === flow.campaignId);
    if (hasCapability(CAPABILITY.CREATE_CAMPAIGN) && !own) {
      const domainSelect = el("select", { id: "setup-domain" }, [el("option", { value: "", text: "Choose a verified company domain…" }),
        ...domains.filter((d) => d.active).map((d) => el("option", { value: d.domain, text: d.domain })),
      ]);
      domainSelect.value = flow.domain || "";
      const selectDomain = button("Select domain", async () => {
        if (!domainSelect.value) { error.textContent = "Choose your company domain first."; return; }
        if (flow.domain !== domainSelect.value) { flow = { domain: domainSelect.value }; csvText = ""; importPreview = null; emailContent = null; }
        flow.domain = domainSelect.value; save(); await redraw();
      }, false, true);
      root.appendChild(card("1. Select domain", [el("label", { for: "setup-domain", text: "Company domain" }), domainSelect,
        selectDomain, button("Add or verify a domain", () => navigateTo("sending")),
        el("p", { text: "Choose the verified domain your recipients use. Domain suggestions do not select or authorize a domain." })]));
      if (flow.domain) {
        const matching = roes.filter((r) => activeRoe(r) && (r.target_domains || []).includes(flow.domain));
        const roe = matching.find((r) => r.roe_id === flow.roeId);
        const roeChoice = el("select", { id: "setup-roe" }, [el("option", { value: "", text: "Choose a signed authorization…" }),
          ...matching.map((r) => el("option", { value: r.roe_id, text: `${r.authorizing_party} — expires ${new Date(r.window_end).toLocaleDateString()}` })),
        ]);
        roeChoice.value = flow.roeId || "";
        const useRoe = button("Use signed RoE", async () => {
          if (!roeChoice.value) { error.textContent = "Select a signed authorization or sign a new RoE."; return; }
          if (flow.roeId !== roeChoice.value) { delete flow.rosterId; delete flow.templateId; emailContent = null; }
          flow.roeId = roeChoice.value; save(); await redraw();
        }, false, true);
        const sign = button("Sign RoE for selected domain", async () => {
          const values = await promptDialog({ title: `Sign RoE for ${flow.domain}`, description: "Confirm the domain owner's authorization for this awareness campaign.", fields: [
            { name: "confirmed", label: "The domain owner has authorized this simulation", type: "checkbox", required: true },
            { name: "party", label: "Authorizing organization or person", type: "text", required: true },
          ], submitLabel: "Sign RoE" });
          if (!values) return;
          const start = new Date(), end = new Date(start); end.setFullYear(end.getFullYear() + 1);
          try {
            const record = await api("/roe", { method: "POST", body: JSON.stringify({ authorizing_party: values.party,
              terms: `${values.party} authorizes a simulated phishing awareness campaign for ${flow.domain}. Recipients are restricted to this domain. Training is disclosed after interaction. Authorization may be revoked.`,
              target_domains: [flow.domain], window_start: start.toISOString(), window_end: end.toISOString() }) });
            flow.roeId = record.roe_id; delete flow.rosterId; save(); await redraw(); toast("RoE signed and selected", "success");
          } catch (e) { fail(error, e); }
        }, !hasCapability(CAPABILITY.SIGN_ROE));
        root.appendChild(card("2. Sign RoE", [el("label", { for: "setup-roe", text: "Saved signed authorization" }), roeChoice, useRoe, sign,
          ...(roe ? [el("p", { class: "policy-banner", role: "status", text: `Per signed RoE, only these domains are approved: ${roe.target_domains.join(", ")}. All others are rejected. This campaign targets ${flow.domain} only.` }),
            el("p", { text: `Signed by ${roe.signer}; valid ${new Date(roe.window_start).toLocaleString()} to ${new Date(roe.window_end).toLocaleString()}.` }),
            el("details", {}, [el("summary", { text: "View signed terms" }), el("p", { text: roe.terms })])] : []),
        ]));
        if (roe) {
          const upload = el("form", { "aria-label": "Upload and review recipients" });
          upload.addEventListener("submit", (e) => e.preventDefault());
          guardUnsavedForm(upload, "Recipient roster");
          upload.append(button("Download CSV template", downloadTemplate), el("p", { text:
            "The blank file is named recipient-roster-template.csv. Your browser saves it to Downloads, or asks you to choose a folder. Fill in email (required), name and department (optional); save as CSV and upload it here. Names personalize greetings when supplied; full names are not required." }));
          const file = field(upload, "Completed recipient CSV", "setup-file", { type: "file", accept: ".csv,text/csv" });
          const text = field(upload, "Or paste the completed CSV", "setup-csv", { rows: "5", maxlength: "524288" }); text.value = csvText;
          const invalidate = () => { importPreview = null; csvText = text.value; };
          text.addEventListener("input", invalidate);
          file.addEventListener("change", async () => {
            if (!file.files[0]) return;
            if (file.files[0].size > 524288) { error.textContent = "CSV must be no larger than 512 KB."; return; }
            text.value = await file.files[0].text(); invalidate();
          });
          const previewNode = el("div");
          const importBody = () => ({ csv_text: csvText, header_mode: "auto", merge_existing: "skip",
            roster_name: `Campaign roster ${new Date().toISOString()}`, roe_id: flow.roeId, target_domain: flow.domain });
          let body = null;
          const validate = button("Review uploaded recipients", async (event) => {
            const btn = event.currentTarget; btn.disabled = true;
            try {
              csvText = text.value; body = importBody();
              importPreview = await api("/recipients/import/preview", { method: "POST", body: JSON.stringify(body) });
              const counts = importPreview.counts;
              previewNode.replaceChildren(el("p", { role: "status", text:
                `Recipients validated against ${flow.domain}, authorized by the selected RoE. New: ${counts.created || 0}; already recorded: ${counts.existing || 0}; rejected: ${(counts.blocked || 0) + (counts.invalid || 0) + (counts.duplicate || 0)}.` }),
                ...((importPreview.errors || []).map((r) => el("p", { text: `Row ${r.row}: ${r.code}` }))));
              if (importPreview.recipients) previewNode.appendChild(table(["Recipient", "Department"], importPreview.recipients.map((r) => [r.display_name ? `${r.display_name} (${r.masked_mailbox})` : r.masked_mailbox, r.department]), "Validated recipients before confirmation"));
              previewNode.appendChild(button("Confirm validated recipients", async (event) => {
                const confirm = event.currentTarget; confirm.disabled = true;
                try {
                  if (!importPreview) throw new Error("The CSV changed. Review the uploaded recipients again.");
                  const result = await api("/recipients/import/apply", { method: "POST", body: JSON.stringify({ ...body, preview_digest: importPreview.preview_digest }) });
                  if (!result.roster) throw new Error("The server did not save a campaign roster.");
                  flow.rosterId = result.roster.audience_group_id; flow.rosterName = result.roster.name; save();
                  csvText = ""; importPreview = null; markFormSaved(upload); await redraw();
                } catch (e) { fail(error, e); } finally { if (confirm.isConnected) confirm.disabled = false; }
              }, !importPreview.can_apply || !(counts.created || counts.existing || counts.updateable), true));
            } catch (e) { fail(error, e); } finally { if (btn.isConnected) btn.disabled = false; }
          }, !hasCapability(CAPABILITY.MANAGE_RECIPIENTS), true);
          upload.append(validate, previewNode);
          markFormSaved(upload);
          if (flow.rosterId) {
            const roster = await boundedCollection(`/recipients?roster_id=${encodeURIComponent(flow.rosterId)}`, "items");
            const confirmed = card("3. Recipients confirmed", [el("p", { role: "status", text: `${roster.length} recipients from this upload only. The whole roster will be sent; no individual selection is required.` }),
              table(["Recipient", "Department", "Status"], roster.map((r) => [r.display_name ? `${r.display_name} (${r.masked_mailbox})` : r.masked_mailbox || r.recipient_id, r.department, r.status]), "Confirmed campaign roster"),
              el("details", {}, [el("summary", { text: "Replace uploaded roster" }), upload])]);
            root.appendChild(confirmed);
          } else root.appendChild(card("3. Upload, review and confirm recipients", [upload]));
          if (flow.rosterId) {
            const choices = templates.filter((t) => t.approval_state === "approved");
            const library = el("select", { id: "setup-library" }, [el("option", { value: "", text: "Choose an email from the library…" }),
              ...choices.map((t) => el("option", { value: t.template_version_id, text: t.subject }))]);
            library.value = flow.sourceTemplateId || "";
            root.appendChild(card("4. Select an email from the library", [el("p", { text:
              "The library provides a starting example. Select one to load its wording, then edit the fake email for your campaign and review it before approval." }),
              el("label", { for: "setup-library", text: "Library email" }), library,
              button("Use this email as a starting point", async () => {
                if (!library.value) { error.textContent = "Choose a library email first."; return; }
                try {
                  emailContent = await api(`/templates/${library.value}/preview`); flow.sourceTemplateId = library.value;
                  delete flow.templateId; save(); await redraw();
                } catch (e) { fail(error, e); }
              }, false, true)]));
            if (flow.sourceTemplateId) {
              if (!emailContent) emailContent = await api(`/templates/${flow.templateId || flow.sourceTemplateId}/preview`);
              const edit = el("form", { "aria-label": "Create campaign email" }); edit.addEventListener("submit", (e) => e.preventDefault());
              guardUnsavedForm(edit, "Campaign email");
              const subject = field(edit, "Email subject", "setup-subject", { required: "", maxlength: "998", value: emailContent.editable_subject || emailContent.subject });
              const wording = field(edit, "Email body", "setup-body", { rows: "9", required: "", maxlength: "200000" });
              wording.value = (emailContent.editable_plain_text || emailContent.plain_text)
                .replace(/\{\{\s*recipient\.first_name(?:\s+or\s+["']colleague["'])?\s*\}\}/g, "[recipient name]")
                .replace(/\{\{\s*tracking\.training_url\s*\}\}/g, "[training link]");
              if (!wording.value.includes("[recipient name]")) wording.value = `Dear [recipient name],\n\n${wording.value}`;
              edit.appendChild(el("p", { text: "The preview shows a sample name. [recipient name] uses the uploaded name for each recipient, or “colleague” when blank. [training link] becomes that recipient’s training link. Review and edit the greeting with the rest of the email." }));
              const previewEmail = button("Create fake email for review", async (event) => {
                const btn = event.currentTarget;
                if (!edit.reportValidity()) return;
                btn.disabled = true;
                try {
                  const draft = await api(`/templates/${flow.sourceTemplateId}/clone`, { method: "POST", body: JSON.stringify({
                    reason: "Campaign email prepared for operator review", subject: subject.value,
                    plain_text: wording.value.replaceAll("[recipient name]", '{{ recipient.first_name or "colleague" }}').replaceAll("[training link]", "{{ tracking.training_url }}") }) });
                  flow.templateId = draft.template_version_id; delete flow.emailApproved; save(); markFormSaved(edit);
                  emailContent = await api(`/templates/${flow.templateId}/preview`); await redraw();
                } catch (e) { fail(error, e); } finally { if (btn.isConnected) btn.disabled = false; }
              }, false, true);
              subject.addEventListener("input", () => { delete flow.templateId; delete flow.emailApproved; save(); });
              wording.addEventListener("input", () => { delete flow.templateId; delete flow.emailApproved; save(); });
              edit.appendChild(previewEmail); markFormSaved(edit);
              root.appendChild(card("5. Create fake email for review", [edit]));
              if (flow.templateId) {
                const preview = card("Email preview", [el("h4", { text: emailContent.subject }),
                  el("pre", { class: "email-preview", text: emailContent.plain_text }),
                  el("p", { text: "Review the subject, wording and sender below. Nothing has been sent." })]); root.appendChild(preview);
                const setup = el("form", { "aria-label": "Approve campaign" }); setup.addEventListener("submit", (e) => e.preventDefault());
                guardUnsavedForm(setup, "Campaign details");
                const title = field(setup, "Campaign name", "setup-title", { required: "", maxlength: "255", value: "" });
                const sender = field(setup, "From email", "setup-sender", { required: "", type: "email", value: `security-awareness@${flow.domain}` });
                const persona = field(setup, "From display name", "setup-persona", { maxlength: "255", value: "Security Awareness" });
                const advanced = el("details", {}, [el("summary", { text: "Delivery window and after-click training page" })]); setup.appendChild(advanced);
                const values = (onboarding?.steps || []).flatMap((s) => s.fields || []);
                let trainingHost = "";
                try { trainingHost = new URL(values.find((f) => f.key.endsWith("_TRAINING_BASE_URL") && f.value)?.value || "").hostname; } catch { /* Explicit entry below. */ }
                const training = field(advanced, "Training hostname", "setup-training", { required: "", value: trainingHost });
                const lesson = el("select", { id: "setup-lesson", required: "" }, lessons.map((l) => el("option", { value: l.training_resource_id, text: l.title })));
                advanced.append(el("label", { for: "setup-lesson", text: "Training lesson after a click" }), lesson);
                const localTime = (d) => new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
                const begin = field(advanced, "Send from (local time)", "setup-start", { required: "", type: "datetime-local", value: localTime(new Date()) });
                const end = field(advanced, "Stop sending after (local time)", "setup-end", { required: "", type: "datetime-local", value: localTime(new Date(Date.now() + 86400000)) });
                const approve = button(sessionInfo()?.approvalPolicy === "enforce" ? "Request campaign approval" : "Approve campaign", async (event) => {
                  const btn = event.currentTarget;
                  const invalid = setup.querySelector(":invalid"); if (invalid) { advanced.open = true; invalid.reportValidity(); invalid.focus(); return; }
                  const approved = await confirmDialog({ title: "Approve this campaign?", message:
                    `Send only the confirmed uploaded roster at ${flow.domain}, using this reviewed email. Nothing is sent until you press Send.`,
                    detail: { "Campaign": title.value, "Email": subject.value, "From": `${persona.value} <${sender.value}>`, "Recipient roster": flow.rosterName, "Authorized domain": flow.domain },
                    confirmLabel: sessionInfo()?.approvalPolicy === "enforce" ? "Request approval" : "Approve" });
                  if (!approved) return; btn.disabled = true;
                  try {
                    const pattern = choices.find((t) => t.template_version_id === flow.sourceTemplateId)?.pattern_id
                      || patterns.find((p) => p.approval_state === "approved")?.campaign_pattern_id;
                    if (!pattern) throw new Error("No approved campaign pattern is available. Open Patterns to approve one.");
                    if (emailContent.approval_state !== "approved") await api(`/templates/${flow.templateId}/decision`, { method: "POST", body: JSON.stringify({ decision: "approved", rationale: "Reviewed campaign email and safe preview" }) });
                    const roster = await boundedCollection(`/recipients?roster_id=${encodeURIComponent(flow.rosterId)}`, "items");
                    const created = await api("/campaigns", { method: "POST", body: JSON.stringify({ delivery_mode: "reviewed_direct", pattern_id: pattern,
                      title: title.value, sender_mailbox: sender.value, sender_display_name: persona.value, training_domain: training.value,
                      schedule_start: new Date(Math.max(new Date(begin.value).getTime(), Date.parse(roe.window_start))).toISOString(), schedule_end: new Date(end.value).toISOString(),
                      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, max_recipients: roster.length,
                      template_version_id: flow.templateId, training_resource_id: lesson.value }) });
                    flow.campaignId = created.campaign_id; save(); markFormSaved(setup);
                    await api(`/campaigns/${flow.campaignId}/audience`, { method: "PUT", body: JSON.stringify({ group_ids: [flow.rosterId], roe_id: flow.roeId }) });
                    const audience = await api(`/campaigns/${flow.campaignId}/audience/preview`);
                    if (audience.included_count !== roster.length || audience.excluded_count) throw new Error("The roster changed or contains newly rejected recipients. Review the current list before approval.");
                    await api(`/campaigns/${flow.campaignId}/confirm`, { method: "POST", body: JSON.stringify({ preview_hash: audience.preview_hash }) });
                    await redraw(); toast("Campaign reviewed. Use Send when ready.", "success");
                  } catch (e) { fail(error, e); } finally { if (btn.isConnected) btn.disabled = false; }
                }, !hasCapability(CAPABILITY.APPROVE_TEMPLATE) || !lessons.length, true);
                setup.append(approve); markFormSaved(setup); root.appendChild(card("6. Approve", [setup]));
              }
            }
          }
        }
      }
    }
    root.appendChild(card("Campaigns and results", []));
    for (const c of campaigns) {
      const section = card(c.title, [el("p", { role: "status", text: `Status: ${c.state}. ${c.delivery_mode === "reviewed_direct" ? "Approved whole-roster send." : "Saved campaign from the previous workflow."}` })]);
      const outcomes = el("div");
      if (c.can_send === true || c.can_publish === true) section.appendChild(button("Send", async (event) => {
        const btn = event.currentTarget;
        const ok = await confirmDialog({ title: `Send ${c.title}?`, message: c.can_publish === true
          ? "Send the approved email to the remaining reviewed recipients. People already sent the earlier test email are not sent twice."
          : "Send the approved email to the complete confirmed roster. The server rechecks the signed RoE and current recipients before queueing.", confirmLabel: "Send" });
        if (!ok) return; btn.disabled = true;
        try {
          const sent = await api(`/campaigns/${c.campaign_id}/${c.can_publish === true ? "publish" : "send"}`, { method: "POST" });
          flow.monitorId = c.campaign_id; save(); await redraw(); toast(`${sent.queued} recipient emails queued. Monitor delivery and clicks in Dashboard.`, "success");
        } catch (e) { fail(error, e); } finally { if (btn.isConnected) btn.disabled = false; }
      }, false, true));
      if (hasCapability(CAPABILITY.CREATE_CAMPAIGN) && (c.state === "draft" || (c.delivery_mode !== "reviewed_direct" && c.state === "approved" && ["reviewed", "unreviewed"].includes(c.launch_gate?.state)))) section.appendChild(button("Review current recipients and approve", async (event) => {
        const btn = event.currentTarget;
        try {
          const preview = await api(`/campaigns/${c.campaign_id}/audience/preview`);
          const email = await api(`/templates/${c.current_template_id}/preview`);
          const { dlg, form } = dialogShell("Review current recipients", `${preview.included_count} included; ${preview.excluded_count} rejected. Nothing is sent by approval.`);
          const authorization = roes.find((r) => r.roe_id === preview.roe_id);
          form.append(el("p", { text: `Approved domains: ${(authorization?.target_domains || []).join(", ") || "No active authorization"}. All other domains are rejected.` }),
            el("h4", { text: email.subject }), el("pre", { class: "email-preview", text: email.plain_text }));
          form.appendChild(table(["Recipient", "Department"], preview.recipients.map((r) => [r.mailbox || r.recipient_id, r.department]), "Recipients for approval"));
          form.appendChild(button("Approve reviewed list", async (event) => {
            const approveBtn = event.currentTarget; approveBtn.disabled = true;
            try { await api(`/campaigns/${c.campaign_id}/confirm`, { method: "POST", body: JSON.stringify({ preview_hash: preview.preview_hash, use_simple_flow: c.delivery_mode !== "reviewed_direct" }) }); dlg.close(); await redraw(); }
            catch (e) { toast(e.message, "error"); } finally { if (approveBtn.isConnected) approveBtn.disabled = false; }
          }, !preview.included_count, true));
          form.appendChild(button("Cancel", () => dlg.close())); openDialog(dlg);
        } catch (e) { fail(error, e); } finally { if (btn.isConnected) btn.disabled = false; }
      }));
      for (const [flag, type, label] of [["can_approve_security", "security", "Approve security review"], ["can_approve_privacy", "privacy", "Approve privacy review"]]) {
        if (c[flag]) section.appendChild(button(label, async () => {
          const ok = await confirmDialog({ title: label, message: `Approve the reviewed email and roster for ${c.title}?`, confirmLabel: "Approve" }); if (!ok) return;
          try { await api(`/campaigns/${c.campaign_id}/approvals/${type}`, { method: "POST", body: JSON.stringify({ decision: "approved", rationale: "Reviewed campaign email and recipients" }) }); await redraw(); } catch (e) { fail(error, e); }
        }));
      }
      if (hasCapability(CAPABILITY.VIEW_NAMED_RESULTS)) section.appendChild(button("Monitor recipient results", () => monitor(c, outcomes)));
      section.appendChild(button("Open dashboard", () => { flow.monitorId = c.campaign_id; save(); navigateTo("dashboard"); }));
      section.appendChild(button("Report and exports", () => showCampaignReport(c)));
      if (c.can_recall) section.appendChild(button("Stop this campaign", async () => {
        if (!await confirmDialog({ title: `Stop ${c.title}?`, message: "Stop future deliveries and disable this campaign's tracking links.", confirmLabel: "Stop campaign", danger: true })) return;
        try { await api(`/campaigns/${c.campaign_id}/recall`, { method: "POST" }); await redraw(); } catch (e) { fail(error, e); }
      }));
      section.appendChild(outcomes); root.appendChild(section);
    }
    if (flow.campaignId) root.appendChild(button("Start a new campaign", async () => {
      flow = {}; csvText = ""; importPreview = null; emailContent = null; save(); await redraw();
    }));
  };
}
