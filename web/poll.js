// Only the request list refreshes; service and permission drafts stay untouched.
const inbox=document.querySelector('[data-inbox]');
if(inbox){setInterval(async()=>{if(document.hidden)return;try{const response=await fetch('/inbox',{credentials:'same-origin',cache:'no-store'});if(response.ok){const doc=new DOMParser().parseFromString(await response.text(),'text/html');const replacement=doc.querySelector('[data-inbox]');if(replacement)inbox.replaceChildren(...replacement.childNodes);}}catch{}},3000);}
