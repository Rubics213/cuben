# Security Recon: indrive.com
## 📜 Javascript Analysis
### 🚨 Found in: https://blog.indrive.com/_next/static/chunks/framework-b9fffb5537caa07c.js
```text
0,"datetime-local":!0,email:!0,month:!0,number:!0,password:!0,range:!0,search:!0,tel:!0,text:!0,time:!0,url:
earch"===e.type||"tel"===e.type||"url"===e.type||"password"===e.type)||"textarea"===t||"true"===e.contentEdi
```
### 🚨 Found in: https://blog.indrive.com/_next/static/chunks/main-bb5857a8e5d5677e.js
```text
type:"redirect-internal",newAs:""+t+e.query+e.hash,newUrl:""+t+e.query+e.
}if("type"in o)if("redirect-internal"===o.type)return this.change(e,o.newUrl,o.newAs,n
=S||null==(y=S.effect)?void 0:y.type)==="redirect-internal"||(null==S||null==(b=S.effect)?void 0:b.type)==="
st.json",b="app-build-manifest.json",P="functions-config-manifest.json",v="subresource-integrity-manifest"
react-loadable-manifest.json",D="server",U=["next.config.js","next.config.mjs","next.config.ts"],F="BUILD_
could not be found",405:"Method Not Allowed",500:"Internal Server Error"
x-next-revalidated-tags",b="x-next-revalidate-tag-token",P="next-resume",v=128,R=256,O=1024,S="_N_T_",T=3
de of your public folder. This conflicts with the internal '/_next' route. https://nextjs.org/docs/messages/
```
### 🚨 Found in: https://blog.indrive.com/_next/static/chunks/pages/_app-afff3565935395bc.js
```text
: https://nextjs.org/docs/messages/invalid-images-config"),"__NEXT_ERROR_CODE",{
config:n,...i
config:t,src:n,unoptimized:i,width:l,quality:o,sizes:r,l
config:t,src:n,quality:o,width:e
config:t,src:n,quality:o,width:s[u]
config:c,src:f,unoptimized:h,width:U,quality:K,sizes:m,l
config:n,src:i,width:l,quality:o
```
### 🚨 Found in: https://blog.indrive.com/_next/static/chunks/polyfills-42372ed130431b0a.js
```text
for(t=Wr(t),e||(s.scheme="",s.username="",s.password="",s.host=null,s.port=null,s.path=[],s.query=null
(s.scheme=r.scheme,o===Wv)s.username=r.username,s.password=r.password,s.host=r.host,s.port=r.port,s.path=vo(
else if("?"===o)s.username=r.username,s.password=r.password,s.host=r.host,s.port=r.port,s.path=vo(
s.username=r.username,s.password=r.password,s.host=r.host,s.port=r.port,s.path=vo(r.path),s.p
}s.username=r.username,s.password=r.password,s.host=r.host,s.port=r.port,s.path=vo(r.path),s.q
s.username=r.username,s.password=r.password,s.host=r.host,s.port=r.port,c=wg;
v?s.password+=y:s.username+=y
return""!==this.username||""!==this.password
var t=this,e=t.scheme,r=t.username,n=t.password,o=t.host,i=t.port,a=t.path,u=t.query,s=t.fragment
return this.password
```
## 🛡️ Vulnerability Scan
