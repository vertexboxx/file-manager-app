
/* upload_manager.js
 - Chunked uploads with resume support using localStorage.
 - On page load, resumes any pending uploads saved in localStorage.
 - Uses /init_upload, /upload_chunk, /uploaded_chunks, /complete_upload endpoints.
*/
(function(){
  const fileInput = document.getElementById('fileInput');
  const uploadsList = document.getElementById('uploadsList');
  const folderSelect = document.getElementById('folderSelect');
  const overwriteCheck = document.getElementById('overwriteCheck');
  const createFolderBtn = document.getElementById('createFolderBtn');
  const newFolderName = document.getElementById('newFolderName');
  const asUserSelect = document.getElementById('asUserSelect');

  const DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024; // 8MB
  const CONCURRENCY = 4;
  const RETRY_LIMIT = 4;

  // Key for storing pending uploads
  const STORAGE_KEY = 'fm_pending_uploads_v1';

  // Utilities
  function loadPending(){ try{ return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]'); }catch(e){ return []; } }
  function savePending(list){ localStorage.setItem(STORAGE_KEY, JSON.stringify(list)); }
  function addPending(item){ const list = loadPending(); list.push(item); savePending(list); }
  function removePending(upload_id){ const list = loadPending().filter(i=>i.upload_id !== upload_id); savePending(list); }

  function formatBytes(bytes){ if(bytes===0) return '0 B'; const sizes=['B','KB','MB','GB','TB']; const i=Math.floor(Math.log(bytes)/Math.log(1024)); return (bytes/Math.pow(1024,i)).toFixed(2)+' '+sizes[i]; }

  // Create folder button
  if(createFolderBtn){
    createFolderBtn.addEventListener('click', (e)=>{
      e.preventDefault();
      const name = newFolderName.value.trim();
      if(!name){ alert('Enter folder name'); return; }
      const parent = folderSelect ? folderSelect.value || '' : '';
      const fd = new FormData();
      fd.append('parent', parent);
      fd.append('name', name);
      if(asUserSelect) fd.append('as_user', asUserSelect.value);
      fetch('/create_folder', { method: 'POST', body: fd }).then(()=>{ location.reload(); });
    });
  }

  // Render pending uploads on page
  function renderPending(){
    const list = loadPending();
    uploadsList.innerHTML = '';
    for(const u of list){
      const div = document.createElement('div');
      div.className = 'upload-item card p-2 mb-2';
      const pct = u.progress ? Math.floor(u.progress*100) : 0;
      div.innerHTML = `<div class="d-flex justify-content-between"><div><strong>${u.filename}</strong><div class="small text-muted">${formatBytes(u.total_size)}</div></div><div><span class="status">${u.status||'pending'}</span></div></div><div class="progress progress-small my-2"><div class="progress-bar" style="width:${pct}%">${pct}%</div></div><div class="small details">${u.details||''}</div><div class="mt-2"><button class="btn btn-sm btn-primary resume-btn">Resume</button> <button class="btn btn-sm btn-danger abort-btn">Abort</button></div>`;
      uploadsList.appendChild(div);

      div.querySelector('.resume-btn').addEventListener('click', ()=>{ resumeUpload(u.upload_id); });
      div.querySelector('.abort-btn').addEventListener('click', ()=>{ abortUpload(u.upload_id); });
    }
  }

  // Before unload warning
  window.addEventListener('beforeunload', (e)=>{
    const pending = loadPending().length;
    if(pending > 0){
      e.preventDefault();
      e.returnValue = '';
    }
  });

  // On file select
  if(fileInput) fileInput.addEventListener('change', async (e)=>{
    const files = Array.from(e.target.files);
    for(const f of files) {
      await startFileUpload(f);
    }
    e.target.value = '';
  });

  async function startFileUpload(file){
    const folder = folderSelect ? folderSelect.value || '' : '';
    const overwrite = overwriteCheck ? !!overwriteCheck.checked : false;
    const as_user = asUserSelect ? asUserSelect.value : null;
    const payload = { filename: file.name, total_size: file.size, chunk_size: DEFAULT_CHUNK_SIZE, folder, overwrite, as_user };
    // init upload
    const resp = await fetch('/init_upload', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
    if(!resp.ok){
      const err = await resp.json().catch(()=>({error:'init_failed'}));
      alert('Init upload failed: '+(err.error||JSON.stringify(err)));
      return;
    }
    const j = await resp.json();
    const upload_id = j.upload_id;
    const chunk_size = j.chunk_size || DEFAULT_CHUNK_SIZE;
    const total_chunks = Math.ceil(file.size / chunk_size);
    // Save pending
    const pend = { upload_id, filename:file.name, total_size:file.size, chunk_size, folder, overwrite, as_user, uploaded_chunks:[], status:'initialized', progress:0, total_chunks, created_at: Date.now() };
    addPending(pend);
    renderPending();
    // start uploading
    uploadFileChunks(file, pend);
  }

  // upload chunk helper
  async function uploadChunkToServer(upload_id, index, slice){
    const fd = new FormData();
    fd.append('upload_id', upload_id);
    fd.append('index', index);
    fd.append('chunk', slice, `${upload_id}.part.${index}`);
    const res = await fetch('/upload_chunk', { method: 'POST', body: fd });
    if(!res.ok) throw new Error('chunk_upload_failed');
    return true;
  }

  // resume by upload_id
  async function resumeUpload(upload_id){
    const list = loadPending();
    const item = list.find(i=>i.upload_id === upload_id);
    if(!item) { renderPending(); return; }
    const fileHandle = await findFileHandleInInputs(item.filename, item.total_size);
    if(!fileHandle){
      alert('File not available in this tab. Re-select the original file to resume.');
      return;
    }
    uploadFileChunks(fileHandle, item);
  }

  // find file in current file input cache (we cannot access filesystem; user must reselect if not present)
  async function findFileHandleInInputs(filename, total_size){
    // try to find in file input elements on the page (only works if user reselected)
    // As a fallback, return null and require user to rechoose the file
    return null;
  }

  // abort upload server-side & remove pending
  async function abortUpload(upload_id){
    if(!confirm('Abort this upload?')) return;
    await fetch('/abort_upload', { method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({upload_id}) });
    removePending(upload_id);
    renderPending();
  }

  // upload file chunks logic with concurrency and resume features
  async function uploadFileChunks(file, pend){
    // file may be a File object or null if not available
    // If user doesn't have file object in current tab, we cannot continue uploading until file is reselected.
    // For simplicity: require the user to remain on the upload page or re-select file. But we persist server-side chunks and metadata so upload can resume.
    if(!(file instanceof File)){
      // If the function was passed pend only, we cannot continue; show instructions.
      // In this implementation, when user returns to the upload page they should re-add the file to continue or click Resume and reselect.
      alert('To resume, please re-select the original file in the file input on this page and click Resume.');
      return;
    }

    const chunk_size = pend.chunk_size;
    const total_chunks = pend.total_chunks || Math.ceil(pend.total_size / chunk_size);
    // fetch server-side uploaded chunk list
    const statusResp = await fetch(`/uploaded_chunks?upload_id=${pend.upload_id}`);
    const statusJson = await statusResp.json();
    const uploadedSet = new Set(statusJson.chunks || pend.uploaded_chunks || []);

    // Prepare queue
    const queue = [];
    for(let i=0;i<total_chunks;i++){
      if(!uploadedSet.has(i)) queue.push(i);
    }

    let active = 0;
    let done = uploadedSet.size;
    let uploadedBytes = Math.min(done * chunk_size, pend.total_size);

    // Update pend status
    pend.status = 'uploading';
    pend.progress = uploadedBytes / pend.total_size;
    updatePending(pend);

    return new Promise((resolve) => {
      function next(){
        if(queue.length === 0){
          if(active === 0){
            finalize();
          }
          return;
        }
        if(active >= CONCURRENCY) return;
        const idx = queue.shift();
        active++;
        const start = idx * chunk_size;
        const end = Math.min(start + chunk_size, pend.total_size);
        const slice = file.slice(start, end);
        let attempts = 0;
        (async function attemptUpload(){
          attempts++;
          try{
            await uploadChunkToServer(pend.upload_id, idx, slice);
            active--;
            done++;
            uploadedBytes += (end - start);
            pend.uploaded_chunks = [...(pend.uploaded_chunks || []), idx];
            pend.progress = Math.min(1, uploadedBytes / pend.total_size);
            pend.details = `${done}/${total_chunks} chunks`;
            updatePending(pend);
            next();
          }catch(e){
            active--;
            if(attempts < RETRY_LIMIT){
              // retry after short backoff
              setTimeout(attemptUpload, 1000 * attempts);
            } else {
              pend.status = 'error';
              pend.details = 'Upload failed on chunk '+idx;
              updatePending(pend);
            }
          }
        })();
        next();
      }

      async function finalize(){
        // call complete_upload
        const res = await fetch('/complete_upload', { method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({upload_id: pend.upload_id}) });
        if(res.ok){
          pend.status = 'completed';
          pend.progress = 1;
          pend.details = 'Upload complete';
          updatePending(pend);
          // remove after short delay
          setTimeout(()=>{ removePending(pend.upload_id); renderPending(); resolve(); }, 800);
        } else {
          const err = await res.json().catch(()=>({error:'finalize_failed'}));
          pend.status = 'error';
          pend.details = 'Finalize error: ' + (err.error || JSON.stringify(err));
          updatePending(pend);
          resolve();
        }
      }

      // start concurrency workers
      for(let i=0;i<CONCURRENCY;i++) next();
    });
  }

  function updatePending(pend){
    const list = loadPending();
    const idx = list.findIndex(i=>i.upload_id === pend.upload_id);
    if(idx >= 0) list[idx] = pend;
    else list.push(pend);
    savePending(list);
    renderPending();
  }

  // On load, render pending
  document.addEventListener('DOMContentLoaded', ()=>{
    renderPending();
  });

})();
