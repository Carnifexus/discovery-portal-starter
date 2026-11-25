'use strict';
const root=document.getElementById('screen'), notice=document.getElementById('notice'), logOut=document.getElementById('logout');
let session=null, matter=null, view='questions', buffers=new Map(), pending=new Map(), saves=new Map();
const phrases={answer:'Answer',true_input:'True to the best of my knowledge',false_input:'Not true to the best of my knowledge',partial_input:'Partly true',unknown:'I don’t know or don’t have it',never_existed:'To my knowledge, this never existed',not_kept:'We don’t keep this type of record',searching:'I’m still searching',help:'Help requested',cannot_find:'I looked and could not find it',clarification:'I don’t understand this request',uploaded:'I uploaded the documents',open:'Open',complete:'Complete','needs-more':'More needed',held:'On hold',accepted:'Accepted',unreviewed:'Ready for review'};
const errors={scanner_unavailable:'The file scanner is unavailable. Nothing was accepted. Please try again later.',scanner_busy:'The scanner is busy. Wait a moment and try again.',unsupported_file_type:'Choose a PDF, Word, Excel, JPG or PNG file.',invalid_filename:'This filename is not supported. Rename the file and try again.',content_type_mismatch:'The file contents do not match its extension.',unsafe_file:'The security scan did not clear this file. It was not accepted.',password_protected_file:'Password-protected PDFs cannot be accepted here.',request_not_accepting_input:'This request is closed or on hold.',file_or_request_too_large:'The file exceeds the 12 MB upload limit.',upload_required:'Upload a document before choosing that response.',invalid_sign_in:'That sign-in didn’t match. Check your username and password.',sign_in_required:'Please sign in again.',wrong_origin:'Refresh this page before trying again.',invalid_request:'Check the information you entered and try again.',malformed_file:'The file could not be read safely. It was not accepted.',active_pdf_content:'This PDF contains active or embedded content and was not accepted.',unsupported_office_content:'This Office file contains unsupported content and was not accepted.',already_assigned:'That person already has this request.',already_submitted:'You already sent a response. Ask counsel to post a follow-up if you need to add to it.',unresolved_request:'Only an answered or completed request can be hidden.',matter_upload_limit:'This intake is at its file limit. Ask counsel how to send the rest.',username_unavailable:'That username is already in use. Choose another.',batch_changed:'This batch changed while you were working. Refresh the page and check the remaining requests.'};
function el(tag,text,cls){const a=document.createElement(tag);if(text!==undefined)a.textContent=text;if(cls)a.className=cls;return a;}
function append(p,...kids){kids.filter(Boolean).forEach(a=>p.append(a));return p;}
function button(text,fn,cls){const a=el('button',text,cls);a.type='button';if(fn)a.addEventListener('click',fn);return a;}
function field(label,input){return append(el('label'),el('span',label),input);}
function link(label,url){const a=el('a',label,'link-button secondary');a.href=url;return a;}
function status(t,error=false){notice.textContent=t;notice.classList.toggle('warn',error);}
function fail(e){status(errors[e.message]||'The request could not be completed. No success was recorded. Please try again.',true);}
const route=(suffix='')=>'/api/matters/'+matter.id+suffix;
async function api(path,method='GET',data,options={}){
 const headers={...options};let body=data;
 if(method!=='GET'&&session)headers['X-CSRF-Token']=session.csrf;
 if(data!==undefined && !(data instanceof Blob)){headers['Content-Type']='application/json';body=JSON.stringify(data);}
 const x=await fetch(path,{method,body,headers,credentials:'same-origin',cache:'no-store',redirect:'error'});
 const r=await x.json();
 if(!x.ok)throw Error(r.error||'request_failed');
 return r;
}
function select(options,val,placeholder){
 const s=el('select');if(placeholder){const w=el('option',placeholder);w.value='';s.append(w);}
 Object.keys(options).forEach(k=>{const a=el('option',options[k]);a.value=k;s.append(a);});
 s.value=val||'';return s;
}
function input(type,name,extra={}){const a=el('input');a.type=type;a.name=name;Object.assign(a,extra);return a;}
function area(val=''){const a=el('textarea');a.maxLength=5000;a.value=val;return a;}
function present(card){root.replaceChildren(card);}
function controls(on){logOut.hidden=!on;}
function showLogin(){
 session=matter=null;view='questions';buffers.clear();pending.forEach(clearTimeout);pending.clear();saves.clear();controls(false);
 const u=input('text','username',{required:true,autocomplete:'username',autocapitalize:'none',maxLength:64});
 const p=input('password','password',{required:true,autocomplete:'current-password',maxLength:256});
 const s=button('Sign in');s.type='submit';
 const f=append(el('form',undefined,'card auth'),el('h1','Sign in'),el('p','Use the username and password counsel gave you.','muted'),field('Username',u),field('Password',p),append(el('div',undefined,'spaced'),s));
 f.addEventListener('submit',async e=>{
  e.preventDefault();s.disabled=true;status('');
  try{await api('/api/sign-in','POST',{username:u.value,password:p.value});p.value='';session=await api('/api/session');await landing();}
  catch(err){fail(err);}finally{s.disabled=false;}
 });present(f);
}
async function landing(){
 controls(true);const rows=await api('/api/matters');
 if(session.role==='client'){if(rows.length!==1)throw Error('request_failed');return openMatter(rows[0].id);}
 const c=append(el('section',undefined,'card hero'),el('h1','Counsel workspace'),el('p','Open a matter to check submissions or review the documents it received.','lead'));
 const group=el('div',undefined,'grid');
 rows.forEach(m=>group.append(button(m.title,()=>openMatter(m.id).catch(fail),'secondary')));
 append(c,group,createIntake());present(c);
}
function createIntake(){
 const panel=append(el('details',undefined,'spaced'),el('summary','Create a new intake'));
 const title=input('text','matter-title',{maxLength:120});const username=input('text','client-username',{autocomplete:'off',autocapitalize:'none',maxLength:64});
 const password=input('password','client-password',{autocomplete:'new-password',minLength:16,maxLength:256});
 const list=el('div');let forms=[];
 const assignAll=input('checkbox','assign-all');
 const imported=area(); imported.maxLength=180000;
 const bulk=append(el('details',undefined,'spaced'),el('summary','Load prepared requests (JSON)'),
  el('p','Paste an array of requests with title, details, and kind (question or documents). Set category to rog, rpd, or rfa. Optional definitions use term, source, exact, and plain. Review the original request language and every explanation before opening access.','hint'),
  field('Prepared request list',imported));
 function add(){
  const r={title:input('text','request-title',{maxLength:150}),details:area(),kind:select({documents:'Collect documents',question:'Ask a question',both:'Both'},'documents')};
  const block=append(el('div',undefined,'file'),field('Request title',r.title),field('Instructions or question',r.details),field('Request type',r.kind));
  append(block,button('Remove this request',()=>{if(forms.length===1){status('Keep at least one request.',true);return;}forms=forms.filter(x=>x!==r);block.remove();},'secondary'));
  forms.push(r);list.append(block);
 }
 add();
 const create=button('Create intake',async()=>{
  if(!title.value.trim()||!/^[a-z0-9][a-z0-9_.-]{2,63}$/.test(username.value)||password.value.length<16||(!imported.value.trim()&&forms.some(r=>!r.title.value.trim()||!r.details.value.trim()))){
   status('Enter a title, a unique lowercase username, a password of at least 16 characters, and instructions for each request.',true);return;
  }
  create.disabled=true;
  try{
   const requests=imported.value.trim()?JSON.parse(imported.value):forms.map(r=>({title:r.title.value,details:r.details.value,kind:r.kind.value}));
   if(!Array.isArray(requests)||!requests.length||requests.length>100){status('Load an array of 1 to 100 prepared requests.',true);return;}
   const y=await api('/api/matters','POST',{title:title.value,username:username.value,password:password.value,requests,assignAll:assignAll.checked});
   password.value='';
   status('Intake created. No invitation was sent.');
   await openMatter(y.id);
  }catch(e){fail(e);}finally{create.disabled=false;}
 });
 return append(panel,el('p','Set up a separate intake for this client. Nothing is sent automatically. Use a different password for every intake.','hint'),
  field('Matter title',title),field('Client username',username),field('Client password',password),field('Assign every imported request to this respondent now',assignAll),el('p','Leave that box unchecked to review the requests and assign each only to the people who should see it.','hint'),bulk,list,
  append(el('div',undefined,'actions'),button('Add another request',()=>{if(forms.length>=100){status('Add no more than 100 requests during setup.',true);return;}add();},'secondary'),create));
}
async function openMatter(id,clear=true){
 if(clear){view='questions';buffers.clear();pending.forEach(clearTimeout);pending.clear();saves.clear();}
 matter=await api('/api/matters/'+id); render();
}
async function refresh(){await openMatter(matter.id,false);}
function draftNow(mid,i){
 if(pending.has(i)){clearTimeout(pending.get(i));pending.delete(i);}
 const b=buffers.get(i);if(!b)return Promise.resolve();
 const snapshot={...b};const before=saves.get(i)||Promise.resolve();
 const call=before.catch(()=>{}).then(()=>api('/api/matters/'+mid+'/requests/'+i+'/draft','POST',snapshot));
 saves.set(i,call);return call;
}
function changeDraft(i,state){buffers.set(i,state);if(pending.has(i))clearTimeout(pending.get(i));
 const m=matter.id;pending.set(i,setTimeout(()=>draftNow(m,i).then(()=>status('Draft saved. Not yet submitted.')).catch(fail),450));}
function showUpload(card,r){
 const key='file-'+r.id;const f=input('file',key,{accept:'.pdf,.docx,.xlsx,.jpg,.jpeg,.png',multiple:true});
 const response=el('p',undefined,'hint hide-empty');response.setAttribute('role','status');
 const btn=button('Upload selected files',async()=>{
  if(!f.files[0]){response.textContent='Choose a file first.';return;}
  const chosen=Array.from(f.files);
  if(chosen.some(file=>file.size>12582912||!file.size)){response.textContent='Choose nonempty files no larger than 12 MB each.';return;}
  btn.disabled=true;response.textContent='Uploading securely…';
  let pending=0,clean=0,blocked=0;const failed=[];
  try{
   for(const file of chosen){
    try{
     const y=await api(route('/requests/'+r.id+'/files'),'POST',file,
       {'Content-Type':'application/octet-stream','X-File-Name':encodeURIComponent(file.name)});
     if(y.status==='clean')clean++;else if(y.status==='blocked')blocked++;else pending++;
    }catch(e){failed.push(file.name+': '+(errors[e.message]||'Could not be saved.'));}
   }
   await refresh();
   status(pending+' pending security check · '+clean+' already cleared · '+blocked+' blocked'+(failed.length?' · '+failed.join(' | '):''),Boolean(failed.length));
  }catch(e){fail(e);}finally{btn.disabled=false;}
 },'secondary');
 append(card,append(el('section',undefined,'upload'),field('Attach one or more files to this request',f),
  el('p','PDF, Word, Excel, JPG or PNG. 12 MB per file. Files stay private and cannot be opened until the security check clears them.','hint'),btn,response));
}
function requestWording(r){
 const original=String(r.details||''); const wording=el('p',undefined,'pre');const defs=(r.definitions||[]).slice().sort((a,b)=>b.term.length-a.term.length);
 const escaped=defs.map(d=>[...d.term].map(c=>'.*+?^${}()|[]'.includes(c)||c.charCodeAt(0)===92?String.fromCharCode(92)+c:c).join(''));
 const boundary=String.fromCharCode(92);
 const matching=escaped.length?new RegExp('(?<!['+boundary+'p{L}'+boundary+'p{N}_])('+escaped.join('|')+')(?!['+boundary+'p{L}'+boundary+'p{N}_])','giu'):null;
 const included=new Set();let pos=0;
 if(matching)for(const match of original.matchAll(matching)){
   wording.append(document.createTextNode(original.slice(pos,match.index)),el('mark',match[0]));
   included.add(match[0].toLowerCase());pos=match.index+match[0].length;
 }
 wording.append(document.createTextNode(original.slice(pos)));
 const terms=defs.filter(d=>included.has(d.term.toLowerCase()));
 if(!terms.length)return [wording];
 const box=append(el('details',undefined,'file'),el('summary','Defined terms and what they mean'));box.open=true;
 for(const d of terms)append(box,append(el('section'),el('strong',d.term),el('p',d.source,'hint'),
   el('p','Exact definition from the request: '+d.exact,'pre'),el('p','In plain English: '+d.plain,'pre')));
 return [wording,box];
}
function clientCard(r,editable){
 const c=append(el('section',undefined,'card'),append(el('div',undefined,'heading-row'),el('h2',r.number+'. '+r.title),el('span',phrases[r.status]||r.status,'pill')),...requestWording(r));
 if(r.quarantine?.length){const q=el('ul');r.quarantine.forEach(f=>q.append(el('li',f.name+' · '+(f.state==='pending'?'security check pending':'did not clear screening'))));append(c,q);}
 if(r.files.length){const u=el('ul');r.files.forEach(f=>u.append(el('li',f.name+' · received')));append(c,u);}
 if(r.followUp)append(c,el('p','Counsel’s reply: '+r.followUp,'follow'));
 if(r.response){append(c,el('p','Submitted: '+(phrases[r.response.kind]||r.response.kind)+(r.response.text?' · '+r.response.text:''),'pre'));}
 if(editable&&r.status!=='complete'&&r.status!=='held'){
  if(!r.response){
   const state=buffers.get(r.id)||r.draft||{kind:'',text:''};buffers.set(r.id,state);
   const options={answer:phrases.answer,unknown:phrases.unknown,clarification:phrases.clarification};
   if(r.category==='rfa'){
     delete options.answer;
     for(const k of ['true_input','false_input','partial_input'])options[k]=phrases[k];
     append(c,el('p','Tell your lawyer what is true, what isn’t, or what you don’t know. This does not admit anything to the other side.','hint'));
   }
   if(r.kind==='documents')options.uploaded=phrases.uploaded;
   const s=select(options,state.kind,'Choose an option'), a=area(state.text);
   const label=el('span','Your answer or a question for counsel');
   const opts=append(el('div'),field('How would you like to respond?',s),append(el('label'),label,a));
   const changed=()=>{label.textContent=s.value==='clarification'?'What would you like counsel to explain?':s.value==='partial_input'?'Which part is true, and which part isn’t?':'Your answer or a note for counsel';changeDraft(r.id,{kind:s.value,text:a.value});};
   if(s.value==='partial_input')label.textContent='Which part is true, and which part isn’t?';
   if(s.value==='clarification')label.textContent='What would you like counsel to explain?';
   s.addEventListener('change',changed);a.addEventListener('input',changed);
   const ask=button('I don’t understand this request',()=>{s.value='clarification';changed();a.focus();},'secondary');
   const save=button('Save draft',()=>draftNow(matter.id,r.id).then(()=>status('Draft saved. Not yet submitted.')).catch(fail),'secondary');
   const send=matter.assignmentsEnabled?button('Send this response',async()=>{
     const data=buffers.get(r.id);
     if(!data?.kind||['answer','partial_input'].includes(data.kind)&&!data.text.trim()){status('Choose a response and add text where needed.',true);return;}
     send.disabled=true;
     try{if(pending.has(r.id)){clearTimeout(pending.get(r.id));pending.delete(r.id);}
       await api(route('/submit'),'POST',{responses:[{id:r.id,...data}]});
       buffers.delete(r.id);saves.delete(r.id);await refresh();status('Response received by your lawyer’s portal.');
     }catch(e){fail(e);}finally{send.disabled=false;}
   }):null;
   append(c,opts,el('p',matter.assignmentsEnabled?'You can send this response without completing any other request.':'Asking for clarification counts as a response when you submit the batch.','hint'),append(el('div',undefined,'actions'),ask,save,send));
  }
  if(r.kind!=='question'||matter.assignmentsEnabled&&r.category==='rog'){
   if(r.kind==='question')append(c,el('p','Supporting documents are optional. You can upload before or after you answer.','hint'));
   showUpload(c,r);
  }
 }
 return c;
}
function selectClientPage(name){
 view=name;status('');renderClient();
}
function productionHistory(r,counsel=false){
 const history=el('div',undefined,'pre');
 for(const v of r.productionUpdates||[]){
  append(history,el('p',phrases[v.kind]+(v.text?' · '+v.text:''),'hint'));
  if(v.reply)append(history,el('p','Counsel’s reply: '+v.reply,'follow'));
  else if(counsel&&v.kind==='help'){
   const a=area();
   const send=button('Reply privately',async()=>{
    if(!a.value.trim())return;
    send.disabled=true;
    try{await api(route('/requests/'+r.id+'/production-help/'+v.id),'POST',{text:a.value});
      await refresh();status('Reply posted in this person’s portal.');}catch(e){fail(e);}finally{send.disabled=false;}
   },'secondary');
   append(history,field('Explanation for this person',a),send);
  }
 }
 return history;
}
function documentCard(r){
 const c=clientCard(r,false);
 append(c,productionHistory(r));
 const reviewable=!['complete','held'].includes(r.status);
 if(!reviewable)return c;
 showUpload(c,r);
 const form=el('div',undefined,'file');
 const heading=el('strong');
 const notes=area();
 let choice='';
 async function tell(kind,text){
   await api(route('/requests/'+r.id+'/production-status'),'POST',{kind,text});
   await refresh();
   status(kind==='searching'?'Marked as still searching. This request stays open.':
          kind==='help'?'Your question was sent privately to your lawyer.':
          'Sent to your lawyer for review, not to the other side.');
 }
 const send=button('Send to my lawyer',async()=>{
  if(!choice||!notes.value.trim()){status('Add a short explanation before sending.',true);return;}
  send.disabled=true;
  try{await tell(choice,notes.value);}catch(e){fail(e);}finally{send.disabled=false;}
 });
 append(form,heading,notes,send);form.hidden=true;
 function reveal(kind,label,hint){
  choice=kind;heading.textContent=label;notes.placeholder=hint;notes.setAttribute('aria-label',hint);notes.value='';form.hidden=false;notes.focus();
 }
 const searching=button('I’m still searching',async()=>{
  searching.disabled=true;
  try{await tell('searching','');}catch(e){fail(e);}finally{searching.disabled=false;}
 },'secondary');
 const help=button('Ask my lawyer for help',()=>reveal('help','Ask my lawyer for help','What do you need help finding or understanding?'),'secondary');
 append(c,append(el('div',undefined,'actions'),help,searching));
 if(!r.response){
  const notKept=button('We don’t keep this type of record',()=>reveal('not_kept',phrases.not_kept,'Explain what records you do keep, and whether someone else might have this.'),'secondary');
  const never=button('I don’t think this ever existed',()=>reveal('never_existed',phrases.never_existed,'Tell your lawyer why you believe this was never created.'),'secondary');
  const absent=button('I looked and couldn’t find it',()=>reveal('cannot_find',phrases.cannot_find,'Tell your lawyer where you looked and whom you asked.'),'secondary');
  const provided=button('I uploaded what I found',async()=>{
    provided.disabled=true;try{await tell('uploaded','');}catch(e){fail(e);}finally{provided.disabled=false;}
  },'secondary');
  append(c,append(el('div',undefined,'actions'),notKept,never,absent,provided));
 }
 append(c,form);
 return c;
}
function discoveryClient(){
 const groups={rog:'Interrogatories (ROGs)',rpd:'Requests for Production (RPDs)',rfa:'Requests for Admission (RFAs)'};
 const current=Object.hasOwn(groups,view)?view:'rog';
 const bucket=id=>matter.requests.filter(r=>r.category===id);
 const nav=el('nav',undefined,'actions');nav.setAttribute('aria-label','Discovery request types');
 for(const [k,label] of Object.entries(groups)){
   const b=button(label+' ('+bucket(k).length+')',()=>selectClientPage(k),current===k?'':'secondary');
   if(current===k)b.setAttribute('aria-current','page');nav.append(b);
 }
 const page=append(el('div'),append(el('section',undefined,'card hero'),el('h1',matter.title),
   el('p','Confidential: For Your Lawyer Only','pill'),
   el('p','These are working answers for counsel, not sworn, final, or sent to the other side. You can start anywhere and return later. Uploading an existing document does not make it privileged.','lead'),
   el('p','This staged preview is for fictional material only.','hint')),nav,
   el('h2',groups[current]),button('Refresh for new responses and upload status',()=>refresh().catch(fail),'secondary'));
 const rows=bucket(current);
 if(!rows.length)append(page,el('p','No requests of this type are assigned to you.'));
 rows.forEach(r=>append(page,current==='rpd'?documentCard(r):clientCard(r,true)));
 present(page);
}
function renderClient(){
 if(matter.assignmentsEnabled)return discoveryClient();
 const documents=matter.assignmentsEnabled?matter.requests.filter(r=>r.kind==='documents'):[];
 const questions=matter.requests.filter(r=>!documents.includes(r));
 const open=questions.filter(r=>!r.response&&!['complete','held'].includes(r.status));const batch=open.slice(0,10);
 const page=append(el('div'),append(el('section',undefined,'card hero'),el('h1',matter.title),el('p','For Your Lawyer Only','pill'),el('p','Tell your counsel what you honestly know, including facts you are unsure about or think may hurt your case. Counsel will review your answers and documents before preparing any formal response. These are not sworn, final, or sent to the court or opposing counsel. Please do not share this page or your login.','lead'),el('p','Uploading an existing document does not by itself make that document privileged. This beta is for test entries and sample files only.','hint'),el('p','Answer up to 10 requests at a time. Add files where requested. When this batch is ready, submit it once. Your answer drafts stay private until you submit.','lead'),
 el('p',open.length+' request'+(open.length===1?'':'s')+' waiting for a response.','pill')));
 if(matter.assignmentsEnabled)append(page,append(el('nav',undefined,'actions'),
    button('Questions',()=>selectClientPage('questions'),'secondary'),
    button('Document production ('+documents.length+')',()=>selectClientPage('documents'),'secondary')));
 if(matter.assignmentsEnabled&&view==='documents'){
   append(page,el('h2','Document production'),
    el('p','All document requests assigned to you are on this page. Add as many responsive files as you have, under the matching request. You can return later and add more.','lead'),
    button('Refresh upload status',()=>refresh().catch(fail),'secondary'));
   if(documents.length)documents.forEach(r=>append(page,documentCard(r)));
   else append(page,el('p','You have no assigned document requests.'));
   present(page);return;
 }
 batch.forEach(r=>page.append(clientCard(r,true)));
 if(batch.length){const submit=button('Send this batch to my lawyer',async()=>{
  const responses=batch.map(r=>({id:r.id,...(buffers.get(r.id)||{kind:'',text:''})}));
  if(responses.some(r=>!r.kind||['answer','partial_input'].includes(r.kind)&&!r.text.trim())){status('Choose a response for each of these requests before you submit.',true);return;}
  submit.disabled=true;
  try{batch.forEach(r=>{if(pending.has(r.id)){clearTimeout(pending.get(r.id));pending.delete(r.id);}});const result=await api(route('/submit'),'POST',{responses});
      batch.forEach(r=>{buffers.delete(r.id);saves.delete(r.id);});
      await refresh();status('Sent to your lawyer for review: '+result.count+' request'+(result.count===1?'':'s')+'.');}
  catch(e){fail(e);}finally{submit.disabled=false;}
 });append(page,append(el('div',undefined,'card'),el('p','For your lawyer’s review only. Nothing here is your final discovery response.','hint'),submit));}
 else append(page,append(el('section',undefined,'card'),el('h2','You’re caught up'),el('p','There are no open requests waiting for a response.')));
 const additional=questions.filter(r=>r.response&&r.status==='needs-more');
 if(additional.length){append(page,el('h2','Counsel needs more'));additional.forEach(r=>page.append(clientCard(r,true)));}
 const sent=questions.filter(r=>(r.response||['complete','held'].includes(r.status))&&!additional.includes(r));
 if(sent.length){const d=append(el('details',undefined,'group'),el('summary','Previously submitted or closed ('+sent.length+')')); sent.forEach(r=>d.append(clientCard(r,Boolean(r.response))));page.append(d);}
 present(page);
}
function reviewControl(endpoint,existing,items,opts={}){
 const s=select(items,existing,''), n=area(opts.note||'');n.maxLength=2000;
 const b=button('Save review',async()=>{b.disabled=true;try{await api(endpoint,'POST',{status:s.value,note:n.value});await refresh();status('Review saved.');}catch(e){fail(e);}finally{b.disabled=false;}},'secondary');
 return append(el('div',undefined,'grid'),field('Review status',s),field('Private note',n),append(el('div',undefined,'spaced'),b));
}
function counselCard(r){
 const c=append(el('section',undefined,'card'),append(el('div',undefined,'heading-row'),el('h2',r.number+'. '+r.title),el('span',phrases[r.status]||r.status,'pill')),el('p',r.details,'pre'));
 c.id='request-'+r.id;
 if(r.respondent)append(c,el('p','Assigned to: '+r.respondent+(r.clientHidden?' · Hidden from respondent':''),'hint'));
 if(r.response){
   append(c,el('p',(phrases[r.response.kind]||r.response.kind)+(r.response.text?': '+r.response.text:''),'pre'));
   if(r.followUp)append(c,el('p','Reply shared with client: '+r.followUp,'follow'));
   else if(r.response.kind==='clarification'){
    const a=area();const b=button('Post explanation',async()=>{b.disabled=true;try{await api(route('/requests/'+r.id+'/follow-up'),'POST',{text:a.value});await refresh();status('Explanation posted inside this portal.');}catch(e){fail(e);}finally{b.disabled=false;}});
    append(c,field('Explanation the client will see',a),b);
   }
 }else append(c,el('p','No submitted response. Drafts are not visible.','muted'));
 if(r.kind==='documents')append(c,productionHistory(r,true));
 if(r.quarantine?.length){const n=r.quarantine.filter(f=>f.state==='pending').length;const b=r.quarantine.length-n;append(c,el('p',n+' uploads pending screening · '+b+' blocked','hint'));}
 r.files.forEach(f=>{
   const row=append(el('div',undefined,'file'),append(el('div',undefined,'heading-row'),el('h3',f.name),el('span',phrases[f.status],'pill')),
    el('p',f.size.toLocaleString()+' bytes · Original retained · Screening passed','hint'),
    link('Download original',route('/files/'+f.fileId)));
   const d=append(el('details'),el('summary','Review file or see its SHA-256'),el('p',f.sha256,'hint'),
    reviewControl(route('/files/'+f.fileId+'/review'),f.status,{accepted:'Accept',held:'Hold for review','needs-more':'More needed'},{note:f.reviewNote}));
   append(row,d);append(c,row);
 });
 return append(c,matter.assignmentsEnabled?assignmentControls(r):null,append(el('details',undefined,'spaced'),el('summary','Review this request'),
   reviewControl(route('/requests/'+r.id+'/review'),r.status,{complete:'Complete','needs-more':'More needed',held:'Hold for review'},{note:r.reviewNote})));
}
function activityPanel(){
 const toggle=append(el('details',undefined,'card'),el('summary','Recent intake activity'));
 const list=el('div');toggle.append(list);
 const matterId=matter.id;
 const label={matter_created:'Intake created',file_received:'File received',batch_submitted:'Batch submitted',request_added:'Request added','follow-up':'Explanation posted',file_reviewed:'File reviewed',review:'Request status reviewed',client_access_revoked:'Client access revoked',request_hidden:'Hidden from respondent',request_reopened:'Shown to respondent',document_status:'Document status submitted',document_progress:'Document progress or help request',document_help_reply:'Private reply posted'};
 async function show(){
  list.textContent='Loading activity…';
  try{
   const data=await api('/api/matters/'+matterId+'/activity');
   if(matter?.id!==matterId)return;
   const rows=el('ul',undefined,'activity');
   data.entries.forEach(x=>{
    const req=matter.requests.find(r=>r.id===x.requestId);
    const when=Intl.DateTimeFormat(undefined,{dateStyle:'medium',timeStyle:'short'}).format(new Date(x.at*1000));
    const detail=(x.count?x.count+' request'+(x.count===1?'':'s'):'');
    const row=append(el('li'),el('strong',label[x.event]),el('span',when+(detail?' · '+detail:''),'hint'));
    if(req){
     const anchor=el('a','Request '+req.number+': '+req.title);anchor.href='#request-'+req.id;
     append(row,anchor);
    }
    append(rows,row);
   });
   list.replaceChildren(data.entries.length?rows:el('p','No activity yet.','muted'));
   if(data.more)append(list,el('p','Showing the most recent activity. The matter report includes the full audit history.','hint'));
   append(list,button('Refresh activity',()=>show(),'secondary'));
  }catch(e){list.textContent='Could not load activity. Close and reopen this panel to retry.';}
 }
 toggle.addEventListener('toggle',()=>{if(toggle.open)show();});
 return toggle;
}

function respondentTools(){
 const box=append(el('details',undefined,'card'),el('summary','Respondents and reminder drafts'));
 const who=input('text','recipient-username',{autocomplete:'off',autocapitalize:'none',maxLength:64});
 const pw=input('password','recipient-password',{autocomplete:'new-password',minLength:16,maxLength:256});
 const add=button('Add respondent',async()=>{
   add.disabled=true;
   try{await api(route('/respondents'),'POST',{username:who.value,password:pw.value});
      pw.value='';await refresh();status('Respondent added. No invitation was sent.');}
   catch(e){fail(e);}finally{add.disabled=false;}
 });
 append(box,field('New username',who),field('Temporary password (16 or more characters)',pw),add);
 for(const r of matter.respondents||[]){
  const list=matter.requests.filter(x=>x.respondentId===r.id&&!x.clientHidden&&
      !['complete','held'].includes(x.status)&&(!x.response||x.status==='needs-more'));
  const item=append(el('div',undefined,'file'),el('strong',r.username),
     el('p',r.active?list.length+' items still open':'Access revoked','hint'));
  if(r.active){
   const reminders=button('Prepare reminder draft',()=>{
     const links=list.map(x=>x.title).join(', ');
     const note=area('Subject: Follow-up on your discovery portal\n\nPlease sign in to the secure portal and review the '+list.length+
       ' items that still need your input'+(links?': '+links:'')+'. Please put answers and documents in the portal rather than replying by email. Thank you.');
     note.readOnly=true;
     append(item,field('Draft only. Confirm the email recipient before sending.',note));
     reminders.disabled=true;note.focus();note.select();
   },'secondary');
   const revoke=button('Revoke access',async()=>{
    if(!window.confirm('Revoke this respondent’s access? The record will be kept.'))return;
    try{await api(route('/respondents/'+r.id+'/revoke'),'POST',{});await refresh();status('Respondent access revoked.');}
    catch(e){fail(e);}
   },'secondary');
   append(item,append(el('div',undefined,'actions'),reminders,revoke));
  }
  append(box,item);
 }
 return box;
}
function assignmentControls(r){
 const people=Object.fromEntries((matter.respondents||[]).filter(x=>x.active&&
   !matter.requests.some(q=>q.rootRequestId===r.rootRequestId&&q.respondentId===x.id)).map(x=>[x.id,x.username]));
 const choose=select(people,'','Select another respondent');
 const assign=button('Assign the same request',async()=>{
   if(!choose.value)return;
   try{await api(route('/requests/'+r.id+'/assignments'),'POST',{respondentId:choose.value});
    await refresh();status('Request assigned. No email was sent.');}catch(e){fail(e);}
 },'secondary');
 const hidden=button(r.clientHidden?'Show again to respondent':'Remove from respondent’s view',async()=>{
   try{await api(route('/requests/'+r.id+'/visibility'),'POST',{visible:Boolean(r.clientHidden)});
       await refresh();status('Visibility updated. Counsel keeps the full record.');}catch(e){fail(e);}
 },'secondary');
 return append(el('div',undefined,'actions'),
   Object.keys(people).length?field('Ask another person',choose):null,Object.keys(people).length?assign:null,
   (r.response||r.status==='complete'||r.clientHidden)?hidden:null);
}
function renderCounsel(){
 const pendingCount=matter.requests.flatMap(r=>r.files).filter(f=>f.status==='unreviewed').length;
 const clarifications=matter.requests.filter(r=>r.response?.kind==='clarification'&&!r.followUp||(r.productionUpdates||[]).some(v=>v.kind==='help'&&!v.reply)).length;
 const page=append(el('div'),append(el('section',undefined,'card hero'),el('h1',matter.title),el('p',pendingCount+' files to review · '+clarifications+' clarification requests waiting','pill'),
 append(el('div',undefined,'actions'),button('All matters',()=>landing().catch(fail),'secondary'),link('Download report',route('/report')))));
 const title=input('text','title',{maxLength:150});const details=area();const kind=select({documents:'Collect documents',question:'Ask a question',both:'Both'},'documents');
 const recipient=select(Object.fromEntries((matter.respondents||[]).filter(x=>x.active).map(x=>[x.id,x.username])),'','Select an active respondent');
 const b=button('Add request',async()=>{
  if(matter.assignmentsEnabled&&!recipient.value){status('Select the respondent who should see this request.',true);return;}
  b.disabled=true;try{await api(route('/requests'),'POST',{title:title.value,details:details.value,kind:kind.value,
   ...(matter.assignmentsEnabled?{respondentId:recipient.value}:{})});
   await refresh();status('Request posted to the selected person’s portal. No email was sent.');
  }catch(e){fail(e);}finally{b.disabled=false;}
 });
 if(matter.assignmentsEnabled)append(page,respondentTools());
 append(page,activityPanel(),append(el('details',undefined,'card'),el('summary','Add a request or follow-up question'),field('Request title',title),field('Instructions',details),field('Request type',kind),matter.assignmentsEnabled?field('Who should answer or provide it?',recipient):null,b));
 const priority=r=>(r.response?.kind==='clarification'&&!r.followUp)||r.files.some(f=>f.status==='unreviewed')||(r.productionUpdates||[]).some(v=>v.kind==='help'&&!v.reply);
 const first=matter.requests.filter(priority), other=matter.requests.filter(r=>!priority(r));
 if(matter.assignmentsEnabled){
   const groups=new Map();matter.requests.forEach(r=>{const id=r.rootRequestId;
    if(!groups.has(id))groups.set(id,[]);groups.get(id).push(r);});
   append(page,el('h2','Discovery review by request'));
   for(const rows of groups.values()){
    const outstanding=rows.filter(r=>r.status!=='complete').length;
    const group=append(el('details',undefined,'group'),el('summary',rows[0].title+' · '+outstanding+' of '+rows.length+' assignments not closed'));
    group.open=rows.some(priority);
    rows.forEach(r=>group.append(counselCard(r)));append(page,group);
   }
 }else{
   if(first.length){append(page,el('h2','Needs review'));first.forEach(r=>page.append(counselCard(r)));}
   if(other.length){append(page,el('h2','Other requests'));other.forEach(r=>page.append(counselCard(r)));}
 }
 present(page);
}
function render(){session.role==='client'?renderClient():renderCounsel();}
logOut.addEventListener('click',async()=>{try{await api('/api/sign-out','POST');status('Signed out.');showLogin();}catch(e){fail(e);}});
(async()=>{try{session=await api('/api/session');await landing();}catch{showLogin();}})();
