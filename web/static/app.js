const $ = (selector, scope = document) => scope.querySelector(selector);
const state = { user: null, csrf: "", roots: [], grants: new Map(), root: null, path: "", entries: [], page: "files", toastTimer: 0, browserPath: "/" };

function toast(message, bad = false) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.toggle("bad", bad);
  node.classList.add("visible");
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => node.classList.remove("visible"), 2800);
}

async function api(url, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json");
  if (options.body && !(options.body instanceof FormData) && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (!["GET", "HEAD", "OPTIONS"].includes(method) && state.csrf) headers.set("X-CSRF-Token", state.csrf);
  const response = await fetch(url, { ...options, method, headers, credentials: "same-origin" });
  const type = response.headers.get("content-type") || "";
  const payload = type.includes("application/json") ? await response.json() : null;
  if (!response.ok) throw new Error(payload?.error || `请求失败 (${response.status})`);
  return payload;
}

function transferRow(name, direction) {
  const list = $("#transfer-list");
  list.hidden = false;
  const row = document.createElement("div"); row.className = "transfer-item";
  const label = document.createElement("span"); label.className = "transfer-name"; label.textContent = `${direction} ${name}`;
  const progress = document.createElement("progress"); progress.max = 100; progress.value = 0; progress.setAttribute("aria-label", `${name}传输进度`);
  const status = document.createElement("span"); status.className = "transfer-status"; status.textContent = "准备中";
  row.append(label, progress, status); list.append(row);
  while (list.children.length > 10) list.firstElementChild.remove();
  const update = (loaded, total, stateText = "传输中") => {
    if (Number.isFinite(total) && total > 0) {
      const percent = Math.min(100, Math.round(loaded * 100 / total));
      progress.value = percent;
      status.textContent = `${formatSize(loaded)} / ${formatSize(total)} · ${percent}% · ${stateText}`;
    } else {
      progress.removeAttribute("value");
      status.textContent = `${formatSize(loaded)} · 总量未知 · ${stateText}`;
    }
    status.classList.toggle("done", stateText === "已完成");
    status.classList.toggle("failed", stateText.startsWith("失败"));
  };
  return { update, done(bytes) { if (bytes === 0) { progress.value = 100; status.textContent = "0 B / 0 B · 100% · 已完成"; status.classList.add("done"); return; } update(bytes, bytes, "已完成"); }, fail(message) { status.textContent = `失败：${message}`; status.classList.add("failed"); } };
}

function requestWithProgress(url, options = {}) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    const method = (options.method || "GET").toUpperCase();
    xhr.open(method, url, true);
    xhr.withCredentials = true;
    if (options.download) xhr.responseType = "blob";
    xhr.setRequestHeader("Accept", options.download ? "application/octet-stream" : "application/json");
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && state.csrf) xhr.setRequestHeader("X-CSRF-Token", state.csrf);
    if (options.uploadProgress) xhr.upload.addEventListener("progress", event => options.uploadProgress(event.loaded, event.lengthComputable ? event.total : 0));
    if (options.downloadProgress) xhr.addEventListener("progress", event => options.downloadProgress(event.loaded, event.lengthComputable ? event.total : 0));
    xhr.addEventListener("error", () => reject(new Error("网络连接失败")));
    xhr.addEventListener("abort", () => reject(new Error("传输已取消")));
    xhr.addEventListener("load", async () => {
      if (xhr.status < 200 || xhr.status >= 300) {
        let message = `请求失败 (${xhr.status})`;
        try {
          const body = options.download ? await xhr.response.text() : xhr.responseText;
          const payload = JSON.parse(body); message = payload.error || message;
        } catch {}
        reject(new Error(message)); return;
      }
      resolve(options.download ? { blob: xhr.response, disposition: xhr.getResponseHeader("Content-Disposition") || "" } : null);
    });
    xhr.send(options.body || null);
  });
}

function saveDownloadedBlob(result, url, fallbackName) {
  let filename = fallbackName;
  const responseURL = new URL(url, window.location.href);
  const path = responseURL.searchParams.get("path") || "";
  if (path) filename = path.split("/").pop() || filename;
  const encoded = result.disposition.match(/filename\*=UTF-8''([^;]+)/i);
  const plain = result.disposition.match(/filename="?([^";]+)"?/i);
  try { if (encoded) filename = decodeURIComponent(encoded[1]); else if (plain) filename = plain[1]; } catch {}
  const objectURL = URL.createObjectURL(result.blob);
  const link = document.createElement("a"); link.href = objectURL; link.download = filename; link.hidden = true;
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(objectURL), 60000);
}

function showLoggedOut() {
  state.user = null;
  state.csrf = "";
  $("#app").hidden = true;
  $("#login-screen").hidden = false;
}

function showLoggedIn() {
  $("#login-screen").hidden = true;
  $("#app").hidden = false;
  $("#identity").textContent = `${state.user.username} · ${state.user.role === "admin" ? "管理员" : "普通用户"}`;
  $("#admin-nav").hidden = state.user.role !== "admin";
  $("#new-folder").hidden = state.user.role !== "admin" && !currentPermissions().createDir;
  $("#upload-label").hidden = state.user.role !== "admin" && !currentPermissions().upload;
  $("#search-input").disabled = state.user.role !== "admin" && !currentPermissions().search;
  $("#search-button").disabled = state.user.role !== "admin" && !currentPermissions().search;
}

async function bootstrap() {
  try {
    const me = await api("/api/me");
    state.user = me.user;
    state.csrf = me.csrfToken;
    showLoggedIn();
    await loadRoots();
  } catch {
    showLoggedOut();
  }
}

async function loadRoots() {
  const data = await api("/api/roots");
  if (state.user.role === "admin") {
    state.roots = data.roots || [];
    state.grants = new Map(state.roots.map(root => [root.id, allPermissions()]));
  } else {
    const grants = data.grants || [];
    state.roots = grants.map(grant => grant.root);
    state.grants = new Map(grants.map(grant => [grant.root.id, grant.permissions]));
  }
  const select = $("#root-select");
  select.replaceChildren();
  for (const root of state.roots) {
    const option = document.createElement("option");
    option.value = String(root.id);
    option.textContent = root.name;
    select.append(option);
  }
  if (!state.roots.length) {
    state.root = null;
    state.path = "";
    renderFiles([]);
    $("#file-notice").textContent = state.user.role === "admin" ? "请先在“共享目录”中添加服务器目录。" : "管理员尚未为你授权共享目录。";
    $("#file-notice").hidden = false;
    return;
  }
  const nextRoot = state.roots.find(root => root.id === state.root?.id) || state.roots[0];
  state.root = nextRoot;
  select.value = String(nextRoot.id);
  $("#file-notice").hidden = true;
  await loadFiles();
}

function allPermissions() { return { list:true, download:true, upload:true, createDir:true, rename:true, delete:true, copy:true, move:true, search:true }; }
function currentPermissions() { return state.root ? (state.grants.get(state.root.id) || {}) : {}; }
function can(key) { return state.user?.role === "admin" || currentPermissions()[key] === true; }

function encodePath(path) { return encodeURIComponent(path || ""); }
async function loadFiles(path = state.path) {
  if (!state.root) return;
  state.path = path;
  try {
    const data = await api(`/api/files?rootId=${state.root.id}&path=${encodePath(path)}`);
    state.entries = data.entries || [];
    $("#file-notice").hidden = true;
    renderFiles(state.entries);
  } catch (error) {
    $("#file-notice").textContent = error.message;
    $("#file-notice").hidden = false;
    renderFiles([]);
  }
  showLoggedIn();
}

function renderFiles(entries, searchMode = false) {
  const tbody = $("#file-rows");
  tbody.replaceChildren();
  const crumbBox = $("#breadcrumbs");
  crumbBox.replaceChildren();
  if (state.root) {
    const parts = state.path ? state.path.split("/") : [];
    const crumbs = [{ label: state.root.name, path: "" }];
    let current = "";
    for (const part of parts) { current = current ? `${current}/${part}` : part; crumbs.push({ label: part, path: current }); }
    crumbs.forEach((crumb, index) => {
      if (index) { const sep = document.createElement("span"); sep.className = "crumb-sep"; sep.textContent = "/"; crumbBox.append(sep); }
      const button = document.createElement("button"); button.className = "crumb"; button.textContent = crumb.label;
      button.addEventListener("click", () => loadFiles(crumb.path)); crumbBox.append(button);
    });
  }
  for (const entry of entries) tbody.append(makeFileRow(entry, searchMode));
  $("#empty-files").hidden = entries.length > 0;
  $("#new-folder").hidden = !state.root || !can("createDir");
  $("#upload-label").hidden = !state.root || !can("upload");
}

function makeFileRow(entry, searchMode) {
  const row = document.createElement("tr");
  const nameCell = document.createElement("td");
  const nameWrap = document.createElement("div"); nameWrap.className = "file-name";
  const icon = document.createElement("span"); icon.className = `file-icon ${entry.kind === "directory" ? "folder" : entry.kind === "symlink" ? "link" : ""}`;
  icon.textContent = entry.kind === "directory" ? "▰" : entry.kind === "symlink" ? "↗" : "▤";
  const name = document.createElement(entry.kind === "directory" && entry.kind !== "symlink" ? "button" : "span");
  name.className = entry.kind === "directory" ? "crumb" : ""; name.textContent = entry.name;
  if (entry.kind === "directory" && entry.kind !== "symlink") name.addEventListener("click", () => loadFiles(entry.path));
  nameWrap.append(icon, name); nameCell.append(nameWrap); row.append(nameCell);
  appendCell(row, entry.kind === "directory" ? "文件夹" : entry.kind === "symlink" ? "符号链接（不可操作）" : "文件");
  appendCell(row, entry.kind === "directory" ? "—" : formatSize(entry.size));
  appendCell(row, formatDate(entry.modTime));
  const actions = document.createElement("td"); actions.className = "actions-col";
  const buttons = document.createElement("div"); buttons.className = "row-actions";
    if (entry.kind !== "symlink" && entry.kind !== "unsupported") {
    if (entry.kind === "file" && can("download")) buttons.append(actionButton("下载", "download", entry, "mini"));
    if (can("rename")) buttons.append(actionButton("重命名", "rename", entry, "mini"));
    if (can("copy")) buttons.append(actionButton("复制", "copy", entry, "mini"));
    if (can("move")) buttons.append(actionButton("移动", "move", entry, "mini"));
    if (can("delete")) buttons.append(actionButton("删除", "delete", entry, "mini danger"));
  }
  actions.append(buttons); row.append(actions);
  if (searchMode) row.dataset.searchPath = entry.path;
  return row;
}

function appendCell(row, value) { const td = document.createElement("td"); td.textContent = value; row.append(td); }
function actionButton(label, action, entry, className) { const b = document.createElement("button"); b.className = className; b.textContent = label; b.dataset.action = action; b.dataset.path = entry.path; b.dataset.name = entry.name; return b; }
function formatSize(size) { if (!Number.isFinite(size)) return "—"; const units = ["B","KB","MB","GB","TB"]; let n = size, i = 0; while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; } return `${i ? n.toFixed(1) : n} ${units[i]}`; }
function formatDate(value) { if (!value) return "—"; const date = new Date(value); return Number.isNaN(date.valueOf()) ? "—" : new Intl.DateTimeFormat("zh-CN", { dateStyle:"medium", timeStyle:"short" }).format(date); }

async function browseServerDirectory(path = "/") {
  const dialog = $("#directory-picker");
  $("#picker-error").textContent = "";
  $("#picker-directories").replaceChildren();
  $("#picker-path").textContent = path;
  state.browserPath = path;
  $("#picker-parent").disabled = path === "/";
  if (!dialog.open) dialog.showModal();
  try {
    const listing = await api(`/api/admin/fs?path=${encodePath(path)}`);
    state.browserPath = listing.path;
    $("#picker-path").textContent = listing.path;
    $("#picker-parent").disabled = !listing.parent;
    const container = $("#picker-directories");
    for (const directory of listing.directories || []) {
      const button = document.createElement("button"); button.type = "button"; button.className = "picker-dir"; button.textContent = `📁 ${directory.name}`;
      button.addEventListener("click", () => browseServerDirectory(directory.path)); container.append(button);
    }
    if (!container.children.length) { const empty = document.createElement("p"); empty.className = "picker-empty"; empty.textContent = "当前目录下没有可访问的子目录。"; container.append(empty); }
  } catch (error) {
    $("#picker-error").textContent = error.message;
  }
}

async function onFileAction(button) {
  const action = button.dataset.action;
  const path = button.dataset.path;
  let activeTransfer = null;
  try {
    if (action === "download") {
      const url = `/api/files/download?rootId=${state.root.id}&path=${encodePath(path)}`;
      activeTransfer = transferRow(button.dataset.name, "下载");
      const result = await requestWithProgress(url, { download:true, downloadProgress:(loaded,total)=>activeTransfer.update(loaded,total) });
      saveDownloadedBlob(result, url, button.dataset.name); activeTransfer.done(result.blob.size); toast(`下载完成：${button.dataset.name}`); return;
    }
    if (action === "delete") {
      if (!window.confirm(`将“${button.dataset.name}”移入回收站？`)) return;
      await api("/api/files/actions", { method:"POST", body:JSON.stringify({ action, rootId:state.root.id, path }) });
      toast("已移入回收站"); await loadFiles(); return;
    }
    if (action === "rename") {
      const name = window.prompt("输入新名称", button.dataset.name); if (!name || name === button.dataset.name) return;
      await api("/api/files/actions", { method:"POST", body:JSON.stringify({ action, rootId:state.root.id, path, name }) });
      toast("已重命名"); await loadFiles(); return;
    }
    if (action === "copy" || action === "move") {
      const targetRoot = await chooseRoot(); if (!targetRoot) return;
      const proposed = targetRoot.id === state.root.id && state.path ? `${state.path}/${button.dataset.name}` : button.dataset.name;
      const destinationPath = window.prompt(`输入目标目录内的完整相对路径（目录：${targetRoot.name}）`, proposed); if (!destinationPath) return;
      await api("/api/files/actions", { method:"POST", body:JSON.stringify({ action, rootId:state.root.id, path, destinationRootId:targetRoot.id, destinationPath }) });
      toast(action === "copy" ? "复制完成" : "移动完成"); await loadFiles();
    }
  } catch (error) { activeTransfer?.fail(error.message); toast(error.message, true); }
}

async function chooseRoot() {
  const targets = state.roots.filter(root => state.user.role === "admin" || state.grants.get(root.id)?.upload === true);
  if (!targets.length) { toast("没有可写入的目标目录", true); return null; }
  if (targets.length === 1) return targets[0];
  const menu = targets.map((root, index) => `${index + 1}. ${root.name}`).join("\n");
  const answer = window.prompt(`选择目标共享目录，输入序号：\n${menu}`, "1");
  const index = Number(answer) - 1; return Number.isInteger(index) && targets[index] ? targets[index] : null;
}

async function loadUsers() {
  const { users } = await api("/api/admin/users");
  const container = $("#users-list"); container.replaceChildren();
  const regularUsers = (users || []).filter(user => user.role === "user");
  for (const user of regularUsers) container.append(await makeUserCard(user));
  if (!regularUsers.length) container.append(emptyMessage("还没有普通用户", "创建账号后，可以为每个共享目录配置独立权限。"));
}

async function makeUserCard(user) {
  const card = document.createElement("article"); card.className = "card";
  const head = document.createElement("div"); head.className = "entity-card"; head.style.padding = "0"; head.style.border = "0"; head.style.boxShadow = "none";
  const main = document.createElement("div"); main.className = "entity-main";
  const title = document.createElement("p"); title.className = "entity-title"; title.textContent = user.username;
  const sub = document.createElement("p"); sub.className = "entity-sub"; sub.textContent = `普通用户 · 创建于 ${formatDate(user.createdAt)}`; main.append(title,sub);
  const actions = document.createElement("div"); actions.className = "entity-actions";
  const badge = document.createElement("span"); badge.className = `badge ${user.active ? "" : "off"}`; badge.textContent = user.active ? "已启用" : "已停用"; actions.append(badge);
  const active = document.createElement("button"); active.className = "mini"; active.textContent = user.active ? "停用" : "启用"; active.addEventListener("click", async()=>{try{await api(`/api/admin/users/${user.id}/active`,{method:"PATCH",body:JSON.stringify({active:!user.active})});toast("账号状态已更新");await loadUsers()}catch(e){toast(e.message,true)}});actions.append(active);
  const remove = document.createElement("button"); remove.className = "mini danger"; remove.textContent = "删除用户"; remove.addEventListener("click",async()=>{if(!window.confirm(`永久删除普通用户“${user.username}”？账号权限和会话将撤销，用户名可重新使用；其回收站内容会保留给管理员处理。`))return;try{await api(`/api/admin/users/${user.id}`,{method:"DELETE"});toast("用户已删除");await loadUsers()}catch(e){toast(e.message,true)}});actions.append(remove);
  const reset = document.createElement("button"); reset.className = "mini"; reset.textContent = "重置密码"; reset.addEventListener("click",async()=>{const password=window.prompt("输入新密码（至少 12 个字符）");if(!password)return;try{await api(`/api/admin/users/${user.id}/password`,{method:"PUT",body:JSON.stringify({password})});toast("密码已重置，旧会话已退出")}catch(e){toast(e.message,true)}});actions.append(reset);
  head.append(main,actions); card.append(head);
  const editor = document.createElement("div"); editor.className = "permission-editor";
  try {
    const data=await api(`/api/admin/users/${user.id}/permissions`);
    for(const grant of data.grants||[])editor.append(permissionSection(user.id,grant));
    if(!(data.grants||[]).length)editor.append(emptyMessage("还没有共享目录","请先添加共享目录。"));
    const save=document.createElement("button");save.className="primary";save.textContent="保存目录权限";save.addEventListener("click",async()=>{try{const grants=[];for(const section of editor.querySelectorAll("[data-root-id]")){const permissions={};section.querySelectorAll("input[data-perm]").forEach(input=>permissions[input.dataset.perm]=input.checked);grants.push({rootId:Number(section.dataset.rootId),permissions})}await api(`/api/admin/users/${user.id}/permissions`,{method:"PUT",body:JSON.stringify({grants})});toast("目录权限已保存")}catch(e){toast(e.message,true)}});editor.append(save);
  }catch(error){editor.textContent=error.message}
  card.append(editor);return card;
}

const PERMS=[["list","浏览"],["download","下载"],["upload","上传"],["createDir","新建目录"],["rename","重命名"],["delete","移入回收站"],["copy","复制"],["move","移动"],["search","搜索"]];
function permissionSection(userID,grant){
  const section=document.createElement("section");section.className="grant-section";section.dataset.rootId=String(grant.root.id);
  const heading=document.createElement("h4");heading.textContent=grant.root.name;section.append(heading);
  const grid=document.createElement("div");grid.className="permission-grid";
  for(const [key,label] of PERMS){const wrap=document.createElement("label");const input=document.createElement("input");input.type="checkbox";input.dataset.perm=key;input.checked=grant.permissions?.[key]===true;const text=document.createElement("span");text.textContent=label;wrap.append(input,text);grid.append(wrap)}
  section.append(grid);return section;
}

async function loadRootAdmin() {
  const {roots}=await api("/api/admin/roots");const list=$("#roots-list");list.replaceChildren();
  for(const root of roots||[]){
    const card=document.createElement("article");card.className="entity-card";
    const main=document.createElement("div");main.className="entity-main";
    const title=document.createElement("p");title.className="entity-title";title.textContent=root.name;
    const sub=document.createElement("p");sub.className="entity-sub";sub.textContent=root.path;main.append(title,sub);
    const side=document.createElement("div");side.className="entity-actions";
    const badge=document.createElement("span");badge.className=`badge ${root.active?"":"off"}`;badge.textContent=root.active?"已共享":"已停用";side.append(badge);
    const toggle=document.createElement("button");toggle.className="mini";toggle.textContent=root.active?"停用目录":"重新启用";
    toggle.addEventListener("click",async()=>{if(root.active&&!confirm(`停用“${root.name}”？用户将无法继续访问。`))return;try{await api(`/api/admin/roots/${root.id}/active`,{method:"PATCH",body:JSON.stringify({active:!root.active})});toast(root.active?"目录已停用":"目录已重新启用");await loadRootAdmin();await loadRoots()}catch(e){toast(e.message,true)}});
    const remove=document.createElement("button");remove.className="mini danger";remove.textContent="删除登记";
    remove.addEventListener("click",async()=>{if(!confirm(`删除共享目录“${root.name}”的登记和授权？服务器上的原目录和文件不会删除；如有待处理回收站内容需先恢复或清理。`))return;try{await api(`/api/admin/roots/${root.id}`,{method:"DELETE"});toast("共享目录登记已删除");await loadRootAdmin();await loadRoots()}catch(e){toast(e.message,true)}});
    side.append(toggle,remove);card.append(main,side);list.append(card)
  }
  if(!roots?.length)list.append(emptyMessage("还没有共享目录","添加服务器目录后，再给普通用户配置权限。"));
}

async function loadTrash(){
  const {entries}=await api("/api/trash");const list=$("#trash-list");list.replaceChildren();
  for(const entry of entries||[]){const card=document.createElement("article");card.className="entity-card";const main=document.createElement("div");main.className="entity-main";const title=document.createElement("p");title.className="entity-title";title.textContent=entry.name;const sub=document.createElement("p");sub.className="entity-sub";sub.textContent=`${entry.rootName} / ${entry.originalPath} · ${formatDate(entry.deletedAt)}`;main.append(title,sub);const actions=document.createElement("div");actions.className="entity-actions";const restore=document.createElement("button");restore.className="mini";restore.textContent="恢复";restore.addEventListener("click",async()=>{try{await api(`/api/trash/${encodeURIComponent(entry.id)}/restore`,{method:"POST",body:"{}"});toast("已恢复");await loadTrash();if(state.page==="files")await loadFiles()}catch(e){toast(e.message,true)}});actions.append(restore);if(state.user.role==="admin"){const purge=document.createElement("button");purge.className="mini danger";purge.textContent="永久清理";purge.addEventListener("click",async()=>{if(!confirm(`永久删除“${entry.name}”？此操作不可恢复。`))return;try{await api(`/api/admin/trash/${encodeURIComponent(entry.id)}`,{method:"DELETE"});toast("已永久清理");await loadTrash()}catch(e){toast(e.message,true)}});actions.append(purge)}card.append(main,actions);list.append(card)}
  if(!entries?.length)list.append(emptyMessage("回收站为空","移入回收站的项目会显示在这里。"));
}

function emptyMessage(titleText,description){const box=document.createElement("div");box.className="empty-state";const title=document.createElement("h2");title.textContent=titleText;const detail=document.createElement("p");detail.textContent=description;box.append(title,detail);return box}

function setPage(page){
  state.page=page;document.querySelectorAll(".page").forEach(node=>node.hidden=node.id!==`page-${page}`);document.querySelectorAll(".nav-item").forEach(node=>node.classList.toggle("active",node.dataset.page===page));
  if(page==="files")loadRoots().catch(e=>toast(e.message,true));if(page==="trash")loadTrash().catch(e=>toast(e.message,true));if(page==="users")loadUsers().catch(e=>toast(e.message,true));if(page==="roots")loadRootAdmin().catch(e=>toast(e.message,true));
}

$("#login-form").addEventListener("submit",async event=>{event.preventDefault();const formEl=event.currentTarget;const form=new FormData(formEl);const error=$("#login-error");error.textContent="";try{const data=await api("/api/auth/login",{method:"POST",body:JSON.stringify({username:form.get("username"),password:form.get("password")})});state.user=data.user;state.csrf=data.csrfToken;formEl.reset();showLoggedIn();await loadRoots()}catch(e){error.textContent=e.message}});
$("#logout").addEventListener("click",async()=>{try{await api("/api/auth/logout",{method:"POST",body:"{}"})}catch{}showLoggedOut()});
document.querySelectorAll(".nav-item").forEach(button=>button.addEventListener("click",()=>setPage(button.dataset.page)));
$("#root-select").addEventListener("change",async event=>{state.root=state.roots.find(root=>String(root.id)===event.target.value)||null;state.path="";await loadFiles()});
$("#new-folder").addEventListener("click",async()=>{if(!state.root)return;const name=prompt("文件夹名称");if(!name)return;try{await api("/api/files/actions",{method:"POST",body:JSON.stringify({action:"create_dir",rootId:state.root.id,path:state.path,name})});toast("文件夹已创建");await loadFiles()}catch(e){toast(e.message,true)}});
$("#upload-input").addEventListener("change",async event=>{
  if(!state.root)return;
  const files=Array.from(event.target.files||[]), rootID=state.root.id, targetPath=state.path;
  for(const file of files){
    const form=new FormData();form.set("path",targetPath);form.set("file",file,file.name);
    const transfer=transferRow(file.name,"上传");
    try{await requestWithProgress(`/api/files/upload?rootId=${rootID}`,{method:"POST",body:form,uploadProgress:(loaded,total)=>transfer.update(loaded,total)});transfer.done(file.size)}
    catch(e){transfer.fail(e.message);toast(`${file.name}：${e.message}`,true)}
  }
  event.target.value="";await loadFiles()
});
$("#file-rows").addEventListener("click",event=>{const button=event.target.closest("button[data-action]");if(button)onFileAction(button)});
$("#search-button").addEventListener("click",async()=>{if(!state.root)return;const q=$("#search-input").value.trim();if(!q){await loadFiles();return}try{const {entries}=await api(`/api/search?rootId=${state.root.id}&path=${encodePath(state.path)}&q=${encodeURIComponent(q)}`);renderFiles(entries||[],true);$("#empty-files").hidden=(entries||[]).length>0;toast(`找到 ${(entries||[]).length} 项`)}catch(e){toast(e.message,true)}});
$("#search-input").addEventListener("keydown",event=>{if(event.key==="Enter")$("#search-button").click()});
$("#create-user-form").addEventListener("submit",async event=>{event.preventDefault();const formEl=event.currentTarget;const form=new FormData(formEl);try{await api("/api/admin/users",{method:"POST",body:JSON.stringify({username:form.get("username"),password:form.get("password")})});formEl.reset();toast("普通用户已创建");await loadUsers()}catch(e){toast(e.message,true)}});
$("#create-root-form").addEventListener("submit",async event=>{event.preventDefault();const formEl=event.currentTarget;const form=new FormData(formEl);try{const name=String(form.get("name")||"");const path=String(form.get("path")||"");const preview=await api("/api/admin/roots/preview",{method:"POST",body:JSON.stringify({path})});if(!window.confirm(`服务器解析后的规范路径为：\n\n${preview.path}\n\n确认添加“${name}”吗？`))return;const result=await api("/api/admin/roots",{method:"POST",body:JSON.stringify({name,path})});formEl.reset();toast(`已添加：${result.root.path}`);await loadRootAdmin();await loadRoots()}catch(e){toast(e.message,true)}});

$("#browse-root-path").addEventListener("click",()=>browseServerDirectory("/"));
$("#picker-parent").addEventListener("click",()=>{const current=state.browserPath;const parent=current==="/"?"/":current.slice(0,current.lastIndexOf("/"))||"/";browseServerDirectory(parent)});
$("#picker-select").addEventListener("click",()=>{$("#create-root-form [name=path]").value=state.browserPath;$("#directory-picker").close()});

bootstrap();
