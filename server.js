const express=require("express");
const path=require("path");
const helmet=require("helmet");
const compression=require("compression");
const rateLimit=require("express-rate-limit");
const {createClient}=require("@supabase/supabase-js");
const app=express();
const PORT=process.env.PORT||10000;
const URL = process.env.SUPABASE_URL;
const KEY = process.env.SUPABASE_ANON_KEY;
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const SITE=process.env.SITE_URL||"https://cptimes.in";
const sb=(URL&&KEY)?createClient(URL,KEY,{auth:{persistSession:false}}):null;
const adminSb = (URL && SERVICE_ROLE_KEY)
  ? createClient(URL, SERVICE_ROLE_KEY, {
      auth: {
        persistSession: false,
        autoRefreshToken: false
      }
    })
  : null;
app.use(helmet({contentSecurityPolicy:false}));
app.use(compression());
app.use(express.json({limit:"2mb"}));
app.use(rateLimit({windowMs:60000,limit:120}));
const PUB=path.join(__dirname,"public");
app.use(express.static(PUB,{maxAge:"1h"}));
const esc=x=>String(x??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
const categorySlug=x=>String(x||"").trim().toLowerCase().replace(/\s+/g,"-");
const bodyHtml=x=>String(x||"").split(/\n{2,}/).map(p=>`<p>${esc(p).replace(/\n/g,"<br>")}</p>`).join("");
async function published(slug){if(!sb)return null;const {data}=await sb.from("articles").select("*").eq("slug",slug).eq("status","published").maybeSingle();return data||null}
app.get("/api/config",(q,r)=>r.json({supabaseUrl:URL||"",supabaseAnonKey:KEY||"",siteUrl:SITE}));
app.get("/api/health", async (q, r) => {
  if (!adminSb) {
    return r.status(503).json({
      ok: false,
      serviceRole: false
    });
  }

  try {
    const { error } = await adminSb
      .from("contributor_allowlist")
      .select("email")
      .limit(1);

    if (error) {
      return r.status(500).json({
        ok: false,
        serviceRole: false,
        error: error.message
      });
    }

    r.json({
      ok: true,
      serviceRole: true
    });

  } catch (err) {
    r.status(500).json({
      ok: false,
      serviceRole: false,
      error: err.message
    });
  }
});
app.get("/api/articles",async(q,r)=>{if(!sb)return r.status(503).json({error:"Supabase not configured"});let x=sb.from("articles").select("id,title,slug,category,excerpt,image_url,author_name,published_at,featured").eq("status","published").order("published_at",{ascending:false}).limit(Math.min(Number(q.query.limit)||12,50));if(q.query.category)x=x.eq("category",q.query.category);const {data,error}=await x;if(error)return r.status(500).json({error:error.message});r.json(data||[])});
app.get("/api/articles/:slug",async(q,r)=>{const a=await published(q.params.slug);if(!a)return r.status(404).json({error:"Not found"});r.json(a)});
app.get("/api/breaking",async(q,r)=>{if(!sb)return r.status(503).json({error:"Supabase not configured"});const {data,error}=await sb.from("breaking_news").select("*").eq("active",true).order("priority",{ascending:false}).order("created_at",{ascending:false}).limit(10);if(error)return r.status(500).json({error:error.message});r.json(data||[])});
app.get("/api/settings",async(q,r)=>{if(!sb)return r.status(503).json({error:"Supabase not configured"});const {data,error}=await sb.from("site_settings").select("key,value");if(error)return r.status(500).json({error:error.message});const o={};(data||[]).forEach(x=>o[x.key]=x.value);r.json(o)});
app.get("/api/fun-facts",async(q,r)=>{if(!sb)return r.status(503).json({error:"Supabase not configured"});let x=sb.from("fun_facts").select("id,title,category,fact,source,language").eq("status","published").order("display_order",{ascending:true}).order("created_at",{ascending:false}).limit(Math.min(Number(q.query.limit)||8,20));if(q.query.language)x=x.eq("language",q.query.language);const {data,error}=await x;if(error)return r.status(500).json({error:error.message});r.set("Cache-Control","public, max-age=300");r.json(data||[])});
app.get("/api/horoscope",async(q,r)=>{if(!sb)return r.status(503).json({error:"Supabase not configured"});const month=/^\d{4}-\d{2}$/.test(q.query.month||"")?`${q.query.month}-01`:new Date().toISOString().slice(0,7)+"-01";const {data,error}=await sb.from("monthly_horoscopes").select("id,month_key,sign,content,language").eq("month_key",month).eq("status","published").order("sign",{ascending:true});if(error)return r.status(500).json({error:error.message});r.set("Cache-Control","public, max-age=3600");r.json(data||[])});
app.get("/sitemap.xml",async(q,r)=>{let u=[SITE,"india","uttar-pradesh","world","business","technology","sports","entertainment","politics"].map(x=>x===SITE?SITE: `${SITE}/category/${x}`);if(sb){const {data}=await sb.from("articles").select("slug,category").eq("status","published").limit(5000);(data||[]).forEach(a=>u.push(`${SITE}/${categorySlug(a.category)}/${encodeURIComponent(a.slug)}`))}r.type("application/xml").send(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${u.map(x=>`<url><loc>${esc(x)}</loc></url>`).join("")}</urlset>`)});
app.get(/^\/(india|uttar-pradesh|world|business|technology|sports|entertainment|politics)\/([^/]+)$/,async(q,r)=>{const a=await published(q.params[1]);if(!a)return r.status(404).send("<h1>Article not found</h1>");const canonical=`${SITE}/${categorySlug(a.category)}/${encodeURIComponent(a.slug)}`;const ld={"@context":"https://schema.org","@type":"NewsArticle","headline":a.title,"description":a.excerpt||a.title,"datePublished":a.published_at,"dateModified":a.updated_at||a.published_at,"author":{"@type":"Person","name":a.author_name||"CP Times Desk"},"publisher":{"@type":"Organization","name":"CP Times","url":SITE}};r.send(`<!doctype html><html lang="hi-IN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${esc(a.title)} | CP Times</title><meta name="description" content="${esc(a.excerpt||a.title)}"><link rel="canonical" href="${esc(canonical)}"><meta property="og:title" content="${esc(a.title)}"><meta property="og:description" content="${esc(a.excerpt||a.title)}">${a.image_url?`<meta property="og:image" content="${esc(a.image_url)}">`:""}<link rel="stylesheet" href="/styles.css"><script type="application/ld+json">${JSON.stringify(ld).replace(/</g,"\\u003c")}</script></head><body><header class="mast"><a href="/"><img src="/cv-news-logo.jpeg" alt="CP Times"></a><a href="/">Home</a></header><main class="article"><span class="tag">${esc(a.category)}</span><h1>${esc(a.title)}</h1><p class="lead">${esc(a.excerpt||"")}</p><div class="meta">By ${esc(a.author_name||"CP Times Desk")} • ${new Date(a.published_at).toLocaleString("en-IN")}</div>${a.image_url?`<img class="article-image" src="${esc(a.image_url)}" alt="${esc(a.title)}">`:""}<div class="article-body">${bodyHtml(a.body)}</div></main></body></html>`)});
app.get("/category/:category",(q,r)=>r.sendFile(path.join(PUB,"category.html")));
app.get("/admin",(q,r)=>r.sendFile(path.join(PUB,"admin.html")));
app.get("/login",(q,r)=>r.sendFile(path.join(PUB,"login.html")));
app.use((q,r)=>r.sendFile(path.join(PUB,"index.html")));
app.listen(PORT,"0.0.0.0",()=>console.log(`CP Times production server running on port ${PORT}`));
