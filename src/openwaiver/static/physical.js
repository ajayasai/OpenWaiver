"use strict";
(() => {
  const $ = id => document.getElementById(id), ns = "http://www.w3.org/2000/svg";
  let access = "", generation = 0, inspection = 0, comparison = 0;
  const status = text => { $("status").textContent = text; };
  function clear() {
    access = ""; generation += 1; inspection += 1; comparison += 1; $("token").value = ""; $("identity").textContent = "Not connected.";
    for (const id of ["before-drawing", "after-drawing", "before-info", "after-info", "runs"]) $(id).replaceChildren();
    $("comparison").textContent = "No comparison requested.";
  }
  async function api(path) {
    if (!access) throw new Error("Connect before reading project evidence.");
    const epoch = generation;
    const response = await fetch(path, {headers: {Authorization: `Bearer ${access}`}, cache: "no-store"});
    if (epoch !== generation) throw new Error("Connection changed; response discarded.");
    if (!response.ok) throw new Error(`Request rejected (${response.status}). Check authorization and selected IDs.`);
    return response.json();
  }
  async function guard(fn) { try { await fn(); } catch (error) { status(error.message); } }
  function pathData(rings, closed = true) {
    return rings.map(r => r.map((p, i) => `${i ? "L" : "M"}${p[0]},${-p[1]}`).join(" ") + (closed ? " Z" : "")).join(" ");
  }
  function draw(prefix, view) {
    const holder = $(prefix + "-drawing"); holder.replaceChildren();
    const svg = document.createElementNS(ns, "svg"); svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", `${prefix} retained geometry for ${view.rule}`);
    const points = view.markers.flatMap(m => m.points).concat(view.shapes.flatMap(p => p.hull));
    const xs = points.map(p => p[0]), ys = points.map(p => p[1]);
    function fit(box) {
      const [x0, y0, x1, y1] = box, w = Math.max(1, x1-x0), h = Math.max(1, y1-y0), pad = .08 * Math.max(w,h);
      svg.setAttribute("viewBox", `${x0-pad} ${-y1-pad} ${w+2*pad} ${h+2*pad}`);
    }
    // Loops avoid spreading up to 250,000 vertices into a JavaScript call stack.
    const extent = values => values.reduce((a,v) => [Math.min(a[0],v),Math.max(a[1],v)], [Infinity,-Infinity]);
    const [xmin,xmax] = extent(xs), [ymin,ymax] = extent(ys);
    const groups = new Map();
    for (const layer of view.recipe.layers) {
      const group = document.createElementNS(ns, "g"); groups.set(layer, group); svg.append(group);
      const button = document.createElement("button"); button.type = "button"; button.className = "layer-toggle";
      button.textContent = layer; button.setAttribute("aria-pressed", "true");
      button.onclick = () => { const hidden = group.getAttribute("visibility") === "hidden";
        group.setAttribute("visibility", hidden ? "visible" : "hidden"); button.setAttribute("aria-pressed", String(hidden)); };
      holder.append(button);
    }
    for (const shape of view.shapes) {
      const node = document.createElementNS(ns, "path"); node.setAttribute("class", "shape");
      node.setAttribute("fill-rule", "evenodd"); node.setAttribute("d", pathData([shape.hull, ...shape.holes]));
      groups.get(shape.layer).append(node);
    }
    for (const marker of view.markers) {
      const node = document.createElementNS(ns, marker.kind === "point" ? "circle" : "path");
      node.setAttribute("class", "marker");
      if (marker.kind === "point") {
        node.setAttribute("cx", marker.points[0][0]); node.setAttribute("cy", -marker.points[0][1]);
        node.setAttribute("r", Math.max(1, (xmax-xmin)/100));
      } else node.setAttribute("d", pathData([marker.points], marker.kind === "polygon"));
      svg.append(node);
    }
    const fitAll = document.createElement("button"); fitAll.type = "button"; fitAll.textContent = "Fit all retained shapes";
    fitAll.onclick = () => fit([xmin,ymin,xmax,ymax]);
    const fitWindow = document.createElement("button"); fitWindow.type = "button"; fitWindow.textContent = "Fit extraction window";
    fitWindow.onclick = () => fit(view.window); holder.append(fitAll,fitWindow,svg); fit([xmin,ymin,xmax,ymax]);
    $(prefix + "-info").textContent = JSON.stringify({rule:view.rule, occurrence:view.occurrence_id,
      dbu_nm:view.recipe.dbu_nm, halo_dbu:view.recipe.halo_dbu, placement:view.placement,
      shapes:view.shapes.length, holes:view.shapes.reduce((n,p)=>n+p.holes.length,0),
      context_sha256:view.context_sha256, layout_sha256:view.layout_sha256},null,2);
  }
  $("login").onsubmit = event => { event.preventDefault(); const entered = $("token").value; clear(); access = entered;
    guard(async () => { const who = await api("/api/me"); $("identity").textContent = `${who.name} · ${who.role} · project-scoped evidence`;
      const runs = await api("/api/runs?limit=1000");
      for (const run of runs.items) {const o=document.createElement("option");o.value=run.id;o.label=`${run.scope.project} / ${run.revision}`;$("runs").append(o);}
      status(`Connected. ${runs.items.length} run IDs suggested; exact IDs may also be entered.`); }); };
  $("logout").onclick = () => {clear();status("Disconnected; evidence and token cleared.");};
  $("inspect").onsubmit = event => {event.preventDefault(); const epoch=generation, request=++inspection;
    guard(async () => {const values=await Promise.all(["before","after"].map(p=>api(`/api/runs/${encodeURIComponent($(p+"-run").value)}/physical/${encodeURIComponent($(p+"-id").value)}`)));
      if(epoch!==generation || request!==inspection)return;draw("before",values[0]);draw("after",values[1]);
      status(values[0].context_sha256===values[1].context_sha256?"Same recorded context digest. Approval validity remains a separate lifecycle decision.":"Physical context differs. Review the retained shapes and placement.");});};
  $("compare").onclick = () => {const epoch=generation, request=++comparison;guard(async () => {const result=await api(`/api/physical/compare/${encodeURIComponent($("before-run").value)}/${encodeURIComponent($("after-run").value)}`);
    if(epoch!==generation || request!==comparison)return;
    $("comparison").textContent=JSON.stringify({...result,correspondences:result.correspondences.slice(0,200),
      displayed:Math.min(200,result.correspondences.length),total:result.correspondences.length},null,2);
    status("Read-only comparison complete. No approvals granted.");});};
})();
